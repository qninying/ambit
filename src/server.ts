// The actual application surface — everything in token.ts/tokenRequest.ts is
// only real, demoable functionality once something can call it. One process,
// one set of in-memory stores for now; a real backing store is a separate
// infrastructure decision, not made here.

import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { AnomalyDetector } from "./anomalyDetector.js";
import { AuditLog } from "./auditLog.js";
import { CircuitOpenError, CircuitBreaker } from "./circuitBreaker.js";
import { InvalidScopeError, PolicyViolationError, UnknownTokenError, enforceToken, revokeToken, type RevocationReason } from "./token.js";
import { delegateToken } from "./delegation.js";
import { RequestNotPendingError, UnknownRequestError, approveRequest, denyRequest, requestToken, type DenialReason } from "./tokenRequest.js";
import { RequestStore } from "./requestStore.js";
import { TokenStore } from "./tokenStore.js";
import { MockEndpointRegistry, type MockSystem } from "./mockEndpoints.js";
import { accessMockEndpoint } from "./mockEndpointAccess.js";
import { InvalidPolicyError, PolicyStore, UnknownPolicyError, createPolicy, modifyPolicy } from "./policy.js";
import { CustomerDataRegistry } from "./customerData.js";
import { InvalidRedactionRuleError, RedactionRuleStore, createRedactionRule } from "./redaction.js";
import { accessCustomerData } from "./customerDataAccess.js";
import { timingSafeStringEqual } from "./timingSafeCompare.js";
import { verifyPassword } from "./passwordHash.js";
import { createSessionToken, verifySessionToken } from "./sessionToken.js";

// ADR-009 hardening: req.session is set only by requireSession (below),
// once a token has genuinely verified — never trusted from anywhere else.
declare global {
  namespace Express {
    interface Request {
      session?: { username: string };
    }
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function envNumber(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : undefined;
}

const auditLog = new AuditLog();
// REQ-008: one shared breaker for both stores — in a real deployment they'd
// likely sit behind the same backing database, so an outage takes both down
// together, not independently. Threshold/cooldown overridable via
// CIRCUIT_BREAKER_FAILURE_THRESHOLD / CIRCUIT_BREAKER_COOLDOWN_MS, same
// "not hardcoded" treatment as every other judgment-call threshold here.
// Only the two trust-relevant transitions (opened, closed) are logged — the
// internal half-open probe waypoint isn't a decision, so it isn't one.
const storeCircuitBreaker = new CircuitBreaker(
  {
    failureThreshold: envNumber("CIRCUIT_BREAKER_FAILURE_THRESHOLD"),
    cooldownMs: envNumber("CIRCUIT_BREAKER_COOLDOWN_MS"),
  },
  (change) => {
    if (change.to === "open") {
      auditLog.record({ subject: "system", action: "policy_token_store", decision: "circuit_opened", reasonCode: change.reason });
    } else if (change.to === "closed") {
      auditLog.record({ subject: "system", action: "policy_token_store", decision: "circuit_closed", reasonCode: change.reason });
    }
  },
);
const tokenStore = new TokenStore(storeCircuitBreaker);
const requestStore = new RequestStore();
const policyStore = new PolicyStore(storeCircuitBreaker);
// Thresholds are a judgment call — overridable without a code change via
// ANOMALY_MAX_SCOPE_BREADTH / ANOMALY_VELOCITY_WINDOW_MS / ANOMALY_MAX_REQUESTS_PER_WINDOW.
const anomalyDetector = new AnomalyDetector({
  maxScopeBreadth: envNumber("ANOMALY_MAX_SCOPE_BREADTH"),
  velocityWindowMs: envNumber("ANOMALY_VELOCITY_WINDOW_MS"),
  maxRequestsPerWindow: envNumber("ANOMALY_MAX_REQUESTS_PER_WINDOW"),
});
const mockEndpoints = new MockEndpointRegistry();
// Same "not hardcoded" treatment via ACCESS_TIMEOUT_MS / ACCESS_MAX_ATTEMPTS / ACCESS_RETRY_DELAY_MS.
const accessConfig = {
  timeoutMs: envNumber("ACCESS_TIMEOUT_MS"),
  maxAttempts: envNumber("ACCESS_MAX_ATTEMPTS"),
  retryDelayMs: envNumber("ACCESS_RETRY_DELAY_MS"),
};

// REQ-009: customer data + redaction. Deliberately NOT wired to
// storeCircuitBreaker — REQ-008 names "Policy & Token Store" specifically;
// extending the breaker's scope to this unrelated dataset wasn't asked for
// and would be scope creep, not thoroughness.
const customerDataRegistry = new CustomerDataRegistry();
const redactionRuleStore = new RedactionRuleStore();
// A real deployment would let a data privacy officer author this through
// POST /redaction-rules like any other rule; a demo needs at least one to
// exist by default so "access customer data" has something to check
// against without a setup step first.
const defaultRedactionRule = createRedactionRule(
  {
    name: "Standard Customer PII",
    sensitiveFields: {
      ssn: "customer:read:ssn",
      email: "customer:read:email",
      phone: "customer:read:phone",
    },
  },
  "system",
  redactionRuleStore,
  auditLog,
);

// ADR-009 hardening: real operator authentication. ADMIN_USERNAME and
// ADMIN_PASSWORD_HASH (generate with `npm run hash-password`, never a raw
// password) are the one configured operator account — right-sized for a
// single-operator demo, not a multi-user IdP integration. SESSION_TTL_MS
// overridable, same "not hardcoded" treatment as every other threshold
// here. No fallback for SESSION_SIGNING_SECRET — if it's unset, sessions
// fail closed rather than silently signing with a default anyone could
// guess by reading this source file.
//
// Read fresh per-request, not cached at module load — same reasoning as
// requireAdminToggleKey's ADMIN_TOGGLE_KEY: rotatable without a restart,
// and testable without a separate module instance per configuration.
function getSessionConfig(): { signingSecret: string; ttlMs?: number } | null {
  const signingSecret = process.env.SESSION_SIGNING_SECRET;
  if (!signingSecret) return null;
  return { signingSecret, ttlMs: envNumber("SESSION_TTL_MS") };
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.post("/auth/login", async (req, res) => {
  const sessionConfig = getSessionConfig();
  const configuredUsername = process.env.ADMIN_USERNAME;
  const configuredHash = process.env.ADMIN_PASSWORD_HASH;
  if (!sessionConfig || !configuredUsername || !configuredHash) {
    res.status(503).json({ error: "authentication is not configured — set ADMIN_USERNAME, ADMIN_PASSWORD_HASH, and SESSION_SIGNING_SECRET" });
    return;
  }
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") {
    res.status(400).json({ error: "username (string) and password (string) are required" });
    return;
  }
  // Username compared timing-safe too — not as sensitive as the password,
  // but there's no reason to leave a cheaper side channel open right next
  // to a hardened one.
  const usernameMatches = timingSafeStringEqual(username, configuredUsername);
  const passwordMatches = await verifyPassword(password, configuredHash);
  if (!usernameMatches || !passwordMatches) {
    auditLog.record({ subject: username, action: "login", decision: "denied", reasonCode: "invalid_credentials" });
    res.status(401).json({ error: "invalid username or password" });
    return;
  }
  auditLog.record({ subject: username, action: "login", decision: "allowed" });
  const token = createSessionToken(username, sessionConfig);
  res.status(200).json({ token });
});

// Applied to every route where the caller's real, verified identity
// matters — starting with approve/deny (ADR-009 item 2: a verified
// approver identity, not a free-text field). Never throws; a missing or
// invalid session is a clean 401, not a crash.
function requireSession(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const sessionConfig = getSessionConfig();
  if (!sessionConfig) {
    res.status(503).json({ error: "authentication is not configured" });
    return;
  }
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!token) {
    res.status(401).json({ error: "missing Authorization: Bearer <token> header" });
    return;
  }
  const result = verifySessionToken(token, sessionConfig);
  if (!result.valid) {
    res.status(401).json({ error: `invalid session: ${result.reason}` });
    return;
  }
  req.session = { username: result.username };
  next();
}

// POST /requests — submit a token request. Sits pending until an approver
// acts on it; no token exists yet.
// Deliberately does NOT accept policyId — see ADR-010. Which policy (if
// any) governs issuance is the approver's decision, made at approval time;
// a requester citing their own policy id at submission time would make
// "policy attached" a self-issued rubber stamp with no real governance
// value. A policyId in the request body here is silently ignored, same as
// any other unrecognized field.
app.post("/requests", (req, res) => {
  const { subject, scope, ttlSeconds, idempotencyKey } = req.body ?? {};
  if (typeof subject !== "string" || !Array.isArray(scope) || typeof ttlSeconds !== "number") {
    res.status(400).json({ error: "subject (string), scope (string[]), and ttlSeconds (number) are required" });
    return;
  }
  const pending = requestToken(
    {
      subject,
      scope,
      ttlSeconds,
      idempotencyKey: typeof idempotencyKey === "string" ? idempotencyKey : undefined,
    },
    requestStore,
    anomalyDetector,
    auditLog,
  );
  res.status(201).json(pending);
});

// GET /requests — what the Consent UI actually displays: requests waiting
// on a human decision.
app.get("/requests", (_req, res) => {
  res.json(requestStore.pending());
});

// GET /requests/:id — a single request, in any status. Needed by anything
// that submits a request and then has to find out what happened to it (the
// SDK, in particular) — GET /requests above only ever returns pending ones,
// so it stops answering the moment a request is decided.
app.get("/requests/:id", (req, res) => {
  const pending = requestStore.get(req.params.id);
  if (!pending) {
    res.status(404).json({ error: `no such request "${req.params.id}"` });
    return;
  }
  res.json(pending);
});

// ADR-009 hardening: approver is now the authenticated session's own
// username — never something the caller types into the request body.
// ADR-010: policyId is still the approver's own choice, made at approval
// time — not inherited from anything the requester submitted.
app.post<{ id: string }>("/requests/:id/approve", requireSession, (req, res) => {
  const approver = req.session!.username;
  const policyId = req.body?.policyId;
  try {
    const token = approveRequest(
      req.params.id,
      requestStore,
      tokenStore,
      auditLog,
      approver,
      typeof policyId === "string" ? policyId : undefined,
      policyStore,
    );
    res.status(200).json(token);
  } catch (err) {
    if (err instanceof UnknownRequestError) {
      res.status(404).json({ error: err.message });
    } else if (err instanceof RequestNotPendingError) {
      res.status(409).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

const VALID_DENIAL_REASONS: DenialReason[] = ["scope_too_broad", "policy_violation", "unverified_subject", "duplicate_request", "other"];

// ADR-009 hardening: approver is the authenticated session's own username,
// same as approve above.
// REQ-010: reasonCode is required here, same treatment as
// POST /tokens/:id/revoke's own reasonCode whitelist — a denial with no
// recorded reason is exactly the gap this story exists to close.
app.post<{ id: string }>("/requests/:id/deny", requireSession, (req, res) => {
  const approver = req.session!.username;
  const reasonCode = req.body?.reasonCode as DenialReason | undefined;
  if (!reasonCode || !VALID_DENIAL_REASONS.includes(reasonCode)) {
    res.status(400).json({ error: `reasonCode must be one of: ${VALID_DENIAL_REASONS.join(", ")}` });
    return;
  }
  try {
    denyRequest(req.params.id, requestStore, auditLog, approver, reasonCode);
    res.status(204).end();
  } catch (err) {
    if (err instanceof UnknownRequestError) {
      res.status(404).json({ error: err.message });
    } else if (err instanceof RequestNotPendingError) {
      res.status(409).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// The Enforcement Gateway (REQ-004), reachable for real — this is what
// STORY-001/002 were missing a demo path for.
app.post("/tokens/:id/enforce", (req, res) => {
  const action = req.body?.action;
  if (typeof action !== "string") {
    res.status(400).json({ error: "action (string) is required" });
    return;
  }
  const decision = enforceToken(req.params.id, action, tokenStore, auditLog);
  res.status(200).json(decision);
});

app.post("/tokens/:id/revoke", (req, res) => {
  const reasonCode = req.body?.reasonCode as RevocationReason | undefined;
  const valid: RevocationReason[] = ["compromised", "no_longer_needed", "policy_violation", "superseded"];
  if (!reasonCode || !valid.includes(reasonCode)) {
    res.status(400).json({ error: `reasonCode must be one of: ${valid.join(", ")}` });
    return;
  }
  try {
    const token = revokeToken(req.params.id, tokenStore, auditLog, reasonCode);
    res.status(200).json(token);
  } catch (err) {
    if (err instanceof UnknownTokenError) {
      res.status(404).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// REQ-003/REQ-012: a subagent's token, narrowed from a parent's. Returns 200
// with approved:false on denial rather than an error status — a refused
// delegation is a normal outcome, not a fault, same treatment as /enforce.
app.post("/tokens/:id/delegate", (req, res) => {
  const { subject, scope, ttlSeconds } = req.body ?? {};
  if (typeof subject !== "string" || !Array.isArray(scope) || typeof ttlSeconds !== "number") {
    res.status(400).json({ error: "subject (string), scope (string[]), and ttlSeconds (number) are required" });
    return;
  }
  const decision = delegateToken(req.params.id, subject, scope, ttlSeconds, tokenStore, auditLog);
  res.status(200).json(decision);
});

// REQ-006/REQ-007: reach a mock endpoint only through the Enforcement
// Gateway. Returns 200 with allowed:false on denial, same treatment as
// /enforce and /delegate — a refused access attempt is a normal outcome.
const MOCK_SYSTEMS: MockSystem[] = ["email", "code-hosting", "payment", "crm"];
app.post("/tokens/:id/access", async (req, res) => {
  const { system, verb } = req.body ?? {};
  if (!MOCK_SYSTEMS.includes(system) || typeof verb !== "string") {
    res.status(400).json({ error: `system must be one of: ${MOCK_SYSTEMS.join(", ")}; verb (string) is required` });
    return;
  }
  const result = await accessMockEndpoint(req.params.id, system, verb, tokenStore, auditLog, mockEndpoints, accessConfig);
  res.status(200).json(result);
});

// Demo/ops convenience: put a mock system into a known-down state so the
// "endpoint is unreachable" path can actually be shown, not just asserted
// in a test. Deliberately not gated behind auth — this only touches the
// in-memory mock registry, never a real system.
app.post("/mock-endpoints/:system/down", (req, res) => {
  const system = req.params.system as MockSystem;
  if (!MOCK_SYSTEMS.includes(system)) {
    res.status(400).json({ error: `system must be one of: ${MOCK_SYSTEMS.join(", ")}` });
    return;
  }
  const down = req.body?.down !== false; // default true — POSTing with no body means "take it down"
  mockEndpoints.setDown(system, down);
  res.status(200).json({ system, down });
});

// REQ-008: current breaker state for the Policy & Token Store — lets an
// operator (or the Console) see whether requests are currently being
// failed closed, without having to trigger one to find out.
app.get("/circuit-breaker", (_req, res) => {
  res.json({ state: storeCircuitBreaker.state() });
});

// Unlike /mock-endpoints/:system/down (which only fakes a downstream
// integration being unavailable — never touches real state), this route
// disables the ENTIRE real Token & Policy Store: every enforce, issue,
// revoke, delegate, and policy operation in the system, for as long as it's
// left on. That is a materially different blast radius, not the same
// "demo convenience" as the mock-endpoint toggle it was originally modeled
// on — an unauthenticated caller could take the whole product down with one
// request and no prior knowledge of any real id. This is a narrow, single-
// route stopgap (a shared secret, not real per-caller identity) pulled
// forward ahead of ADR-009's full hardening phase specifically because of
// that severity — see ADR-009's "What would change this decision."
function requireAdminToggleKey(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const configuredKey = process.env.ADMIN_TOGGLE_KEY;
  if (!configuredKey) {
    res.status(403).json({ error: "fault-injection routes are disabled — set ADMIN_TOGGLE_KEY to enable them" });
    return;
  }
  // Constant-time — this is the one real secret comparison anywhere in this
  // codebase, so it's the one place a plain !== (which short-circuits at
  // the first differing character) is actually worth the fix.
  if (!timingSafeStringEqual(req.header("x-ambit-admin-key") ?? "", configuredKey)) {
    res.status(403).json({ error: "missing or invalid x-ambit-admin-key header" });
    return;
  }
  next();
}

app.post("/circuit-breaker/simulate-outage", requireAdminToggleKey, (req, res) => {
  const down = req.body?.down !== false;
  storeCircuitBreaker.simulateOutage(down);
  // The toggle call itself is a real, audit-worthy fact distinct from the
  // breaker's own state-machine transitions (onStateChange, above) — an
  // operator investigating "why did this trip" needs to see that someone
  // deliberately engaged fault injection, even on a call where the real
  // failure threshold hasn't been crossed yet. actor distinguishes this
  // from the state machine's own organic transitions (subject: "system",
  // no actor).
  auditLog.record({
    subject: "system",
    action: "circuit_breaker_simulate_outage",
    decision: down ? "circuit_opened" : "circuit_closed",
    actor: "admin-toggle",
    reasonCode: "manual_fault_injection",
  });
  res.status(200).json({ down, state: storeCircuitBreaker.state() });
});

// GET /tokens — the console's Tokens tab. Every token this process has
// issued, active or revoked; no filtering, the UI decides how to slice it.
app.get("/tokens", (_req, res) => {
  res.json(tokenStore.list());
});

// REQ-011/REQ-017: human-authored policies. PATCH, not PUT — a policy
// modification is a partial change (name/allowedScope/maxTtlSeconds
// individually), not a full replacement.
app.post("/policies", (req, res) => {
  const { name, allowedScope, maxTtlSeconds, authoredBy } = req.body ?? {};
  if (typeof name !== "string" || !Array.isArray(allowedScope) || typeof maxTtlSeconds !== "number" || typeof authoredBy !== "string") {
    res.status(400).json({ error: "name (string), allowedScope (string[]), maxTtlSeconds (number), and authoredBy (string) are required" });
    return;
  }
  try {
    const policy = createPolicy({ name, allowedScope, maxTtlSeconds }, authoredBy, policyStore, auditLog);
    res.status(201).json(policy);
  } catch (err) {
    if (err instanceof InvalidPolicyError) {
      res.status(400).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

app.get("/policies", (_req, res) => {
  res.json(policyStore.list());
});

app.patch("/policies/:id", (req, res) => {
  const { name, allowedScope, maxTtlSeconds, authoredBy } = req.body ?? {};
  if (typeof authoredBy !== "string") {
    res.status(400).json({ error: "authoredBy (string) is required" });
    return;
  }
  try {
    const policy = modifyPolicy(
      req.params.id,
      {
        name: typeof name === "string" ? name : undefined,
        allowedScope: Array.isArray(allowedScope) ? allowedScope : undefined,
        maxTtlSeconds: typeof maxTtlSeconds === "number" ? maxTtlSeconds : undefined,
      },
      authoredBy,
      policyStore,
      auditLog,
    );
    res.status(200).json(policy);
  } catch (err) {
    if (err instanceof UnknownPolicyError) {
      res.status(404).json({ error: err.message });
    } else if (err instanceof InvalidPolicyError) {
      res.status(400).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// REQ-009: field-level redaction rules. POST-only (no PATCH) — this
// story's acceptance criteria don't ask for "modified rule, changes are
// applied" the way STORY-007 did for policies, so that surface wasn't
// built; a new rule is how a mistaken one gets superseded for now.
app.post("/redaction-rules", (req, res) => {
  const { name, sensitiveFields, authoredBy } = req.body ?? {};
  if (typeof name !== "string" || typeof sensitiveFields !== "object" || sensitiveFields === null || Array.isArray(sensitiveFields) || typeof authoredBy !== "string") {
    res.status(400).json({ error: "name (string), sensitiveFields (object mapping field name to required scope), and authoredBy (string) are required" });
    return;
  }
  try {
    const rule = createRedactionRule({ name, sensitiveFields }, authoredBy, redactionRuleStore, auditLog);
    res.status(201).json(rule);
  } catch (err) {
    if (err instanceof InvalidRedactionRuleError) {
      res.status(400).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

app.get("/redaction-rules", (_req, res) => {
  res.json(redactionRuleStore.list());
});

// REQ-009: the actual data-access path. Always the server's own configured
// default rule — deliberately NOT reading a redactionRuleId from the
// request body. A caller choosing which rule grades their own access would
// let anyone with an unauthenticated POST to /redaction-rules (every route
// here is unauthenticated per ADR-009) create a trivially-weak rule and
// select it on their own request, bypassing redaction entirely regardless
// of how caller authentication eventually gets added — that's a design
// flaw in what gets exposed over HTTP, not something auth alone would fix.
// accessCustomerData() itself still takes a rule id as a real parameter
// (used directly by callers who aren't the HTTP boundary, e.g. tests) —
// this route is the trust boundary that pins it, not the function.
app.post("/tokens/:id/customer-data/:customerId", (req, res) => {
  const result = accessCustomerData(
    req.params.id,
    req.params.customerId,
    tokenStore,
    auditLog,
    customerDataRegistry,
    redactionRuleStore,
    defaultRedactionRule.id,
  );
  res.status(200).json(result);
});

app.get("/audit-log", (_req, res) => {
  res.json(auditLog.entries());
});

// Proves the log is tamper-evident, not just labelled immutable — walks the
// real hash chain and reports exactly which entry it breaks at, if any.
app.get("/audit-log/verify", (_req, res) => {
  res.json(auditLog.verify());
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof InvalidScopeError || err instanceof PolicyViolationError) {
    res.status(400).json({ error: err.message });
    return;
  }
  // REQ-008: the store is failing closed — 503, not 500. This is the
  // expected, correctly-handled shape of an outage, not an unexpected bug.
  if (err instanceof CircuitOpenError) {
    res.status(503).json({ error: err.message });
    return;
  }
  // Never swallow an error — log the real one, but don't leak internals to the caller.
  console.error(err);
  res.status(500).json({ error: "internal error" });
});

// Only bind a real port when this file is run directly (`npm run start`),
// not when it's imported — the SDK's own tests import `app` and bind it to
// an ephemeral port themselves, to exercise the real HTTP stack without
// colliding with a live dev server on the same fixed port.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 4000;
  const server = app.listen(port, () => {
    console.log(`ambit server listening on :${port}`);
  });

  // Disposability (12-factor): shut down cleanly on SIGTERM rather than being killed hard.
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}

export { app };
