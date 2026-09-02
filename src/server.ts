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
import { InvalidScopeError, PolicyViolationError, UnknownTokenError, enforceToken, revokeToken, type RevocationReason, type Token } from "./token.js";
import { delegateToken } from "./delegation.js";
import {
  RequestNotApprovedError,
  RequestNotPendingError,
  TokenSecretAlreadyClaimedError,
  UnauthorizedDeciderError,
  UnknownRequestError,
  WrongSubjectError,
  approveRequest,
  checkRequestTimeout,
  claimTokenSecret,
  denyRequest,
  requestToken,
  type DenialReason,
} from "./tokenRequest.js";
import { RequestStore } from "./requestStore.js";
import { TokenStore } from "./tokenStore.js";
import { MockEndpointRegistry, type MockSystem } from "./mockEndpoints.js";
import { accessMockEndpoint } from "./mockEndpointAccess.js";
import { InvalidPolicyError, PolicyStore, UnknownPolicyError, createPolicy, modifyPolicy } from "./policy.js";
import { CustomerDataRegistry } from "./customerData.js";
import { InvalidRedactionRuleError, RedactionRuleStore, createRedactionRule } from "./redaction.js";
import { accessCustomerData } from "./customerDataAccess.js";
import { timingSafeStringEqual } from "./timingSafeCompare.js";
import { createSessionToken, verifySessionToken } from "./sessionToken.js";
import { AgentIdentityStore, DuplicateAgentIdentityError, InvalidAgentIdentityError, authenticateAgent, registerAgentIdentity } from "./agentIdentity.js";
import { RateLimiter } from "./rateLimiter.js";
import { TotpVerifier } from "./totp.js";
import { findAuthenticatedOperator, type OperatorIdentity } from "./operatorDirectory.js";
import { logEvent } from "./logger.js";

// ADR-009 hardening: req.session is set only by requireSession (below),
// once a session token has genuinely verified — never trusted from
// anywhere else. req.agentIdentity is set only by requireAgentCredential,
// once an agent credential has genuinely verified, same reasoning.
declare global {
  namespace Express {
    interface Request {
      session?: { username: string };
      agentIdentity?: { subject: string };
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

// ADR-014: one directory, not six separate env vars — every store's JSONL
// file lives under it, named for the store. Unset (the default, and every
// existing test's behavior) means every store stays purely in-memory,
// exactly as before this ADR. Set it to survive a restart.
const dataDir = process.env.AMBIT_DATA_DIR;
function dataFile(name: string): string | undefined {
  return dataDir ? path.join(dataDir, `${name}.jsonl`) : undefined;
}

// ADR-018: rotation threshold overridable, same "not hardcoded" treatment
// as every other judgment-call threshold here — AUDIT_LOG_MAX_LINES_PER_SEGMENT.
const auditLog = new AuditLog(dataFile("audit-log"), { maxLinesPerSegment: envNumber("AUDIT_LOG_MAX_LINES_PER_SEGMENT") });
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
const tokenStore = new TokenStore(storeCircuitBreaker, dataFile("tokens"));
const requestStore = new RequestStore(dataFile("requests"));
const policyStore = new PolicyStore(storeCircuitBreaker, dataFile("policies"));
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

// ADR-016 (Control hardening, second slice): closes the rate-limiting gap
// the INPACT trust scorecard named — grepping this repo for one turned up
// nothing, so POST /auth/login accepted unlimited password guesses and no
// route had any flood protection at all. Login gets a deliberately stricter
// limiter than the general one, since it's the one route where a tight
// limit closes a real brute-force gap rather than just generic abuse
// protection. Both overridable via env vars, same "not hardcoded" treatment
// as every other threshold here — RATE_LIMIT_GENERAL_MAX_REQUESTS /
// RATE_LIMIT_GENERAL_WINDOW_MS / RATE_LIMIT_LOGIN_MAX_REQUESTS /
// RATE_LIMIT_LOGIN_WINDOW_MS.
const generalRateLimiter = new RateLimiter({
  windowMs: envNumber("RATE_LIMIT_GENERAL_WINDOW_MS") ?? 60_000,
  maxRequests: envNumber("RATE_LIMIT_GENERAL_MAX_REQUESTS") ?? 120,
});
const loginRateLimiter = new RateLimiter({
  windowMs: envNumber("RATE_LIMIT_LOGIN_WINDOW_MS") ?? 60_000,
  maxRequests: envNumber("RATE_LIMIT_LOGIN_MAX_REQUESTS") ?? 5,
});

// Keyed by socket remote address, not X-Forwarded-For — this server has no
// reverse proxy in front of it in any deployment this repo actually
// targets, so the socket address is the real, unspoofable client address
// rather than a header a caller could just set themselves.
function clientKey(req: express.Request): string {
  return req.socket.remoteAddress ?? "unknown";
}

// ADR-017: closes the INPACT Identity dimension's remaining named gap — no
// second factor on operator login. Not constructed once at module load
// (this module is imported statically by most test files before their own
// beforeAll() sets ADMIN_TOTP_SECRET, so an at-import-time read would always
// see it unset there — the same class of bug getSessionConfig()'s
// read-fresh-per-request comment above already calls out) and not
// reconstructed on every request either (a fresh TotpVerifier per request
// has no memory of the last accepted code, silently disabling its own
// replay protection). Rebuilt only when a given secret's own configured
// value actually changes, so replay-protection state survives every
// request that keeps using the same real secret, and a rotation is picked
// up without a restart — same rotatable-without-restart intent as
// SESSION_SIGNING_SECRET.
//
// ADR-019: keyed by secret, not a single cached slot — once a second real
// operator identity can exist, two different secrets are in play on the
// same server at once, and a single-slot cache would evict one identity's
// verifier (silently wiping its replay-protection state) every time a
// login attempt checked the other.
const totpVerifierCache = new Map<string, TotpVerifier>();
function getTotpVerifier(secret: string): TotpVerifier {
  let verifier = totpVerifierCache.get(secret);
  if (!verifier) {
    verifier = new TotpVerifier(secret);
    totpVerifierCache.set(secret, verifier);
  }
  return verifier;
}

// ADR-019: an identity's three env vars are all-or-nothing — a partially
// set identity (e.g. BACKUP_APPROVER_USERNAME set but not the other two) is
// almost certainly a misconfiguration, not a deliberate partial feature.
// Failing closed and saying so beats silently skipping it and leaving an
// operator believing a backup approver is live when it isn't.
function resolveOperatorIdentity(
  username: string | undefined,
  passwordHash: string | undefined,
  totpSecret: string | undefined,
): OperatorIdentity | null | "misconfigured" {
  const setCount = [username, passwordHash, totpSecret].filter((v) => v !== undefined).length;
  if (setCount === 0) return null;
  if (setCount < 3) return "misconfigured";
  return { username: username!, passwordHash: passwordHash!, totpVerifier: getTotpVerifier(totpSecret!) };
}

function sendRateLimited(res: express.Response, retryAfterMs: number): void {
  res.setHeader("Retry-After", Math.ceil(retryAfterMs / 1000).toString());
  res.status(429).json({ error: "rate limit exceeded — try again shortly" });
}

// REQ-009: customer data + redaction. Deliberately NOT wired to
// storeCircuitBreaker — REQ-008 names "Policy & Token Store" specifically;
// extending the breaker's scope to this unrelated dataset wasn't asked for
// and would be scope creep, not thoroughness.
const customerDataRegistry = new CustomerDataRegistry();
const redactionRuleStore = new RedactionRuleStore(dataFile("redaction-rules"));
// A real deployment would let a data privacy officer author this through
// POST /redaction-rules like any other rule; a demo needs at least one to
// exist by default so "access customer data" has something to check
// against without a setup step first.
// ADR-014: reuses a rehydrated default rule if one already exists rather
// than unconditionally creating a new one on every boot — createRedactionRule
// always mints a fresh id, so without this check, persistence would append a
// new "Standard Customer PII" rule (with a new id, new audit entry) on every
// single restart, the exact "works once but breaks on retry" idempotency
// violation CLAUDE.md calls out as a production defect, not a nitpick.
const defaultRedactionRule =
  redactionRuleStore.list().find((r) => r.name === "Standard Customer PII") ??
  createRedactionRule(
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

// ADR-009 hardening: closes requester-identity spoofing on POST /requests
// — "subject" used to be whatever the caller typed into the request body.
// Deliberately NOT wired to storeCircuitBreaker, same reasoning as
// customerDataRegistry/redactionRuleStore above — REQ-008 names "Policy &
// Token Store" specifically.
const agentIdentityStore = new AgentIdentityStore(dataFile("agent-identities"));

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// ADR-016: general flood backstop across the whole API — deliberately placed
// after express.static so a normal page load (fetching the console's own
// JS/CSS) never counts against it; only requests that fall through to the
// actual API routes below do.
app.use((req, res, next) => {
  const result = generalRateLimiter.check(clientKey(req));
  if (!result.allowed) {
    sendRateLimited(res, result.retryAfterMs);
    return;
  }
  next();
});

// ADR-016: deliberately stricter than the general limiter above — this is
// the one route where a tight limit closes a real brute-force gap (guessing
// the operator's password) rather than just generic flood protection.
function requireLoginRateLimit(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const result = loginRateLimiter.check(clientKey(req));
  if (!result.allowed) {
    sendRateLimited(res, result.retryAfterMs);
    return;
  }
  next();
}

app.post("/auth/login", requireLoginRateLimit, async (req, res) => {
  const sessionConfig = getSessionConfig();
  const primary = resolveOperatorIdentity(process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD_HASH, process.env.ADMIN_TOTP_SECRET);
  // ADR-019: BACKUP_APPROVER_* is deliberately optional and NOT fail-fast
  // the way the primary's three vars are — leaving it unset keeps this a
  // single-operator deployment exactly as it worked before, matching
  // CoreOps's own ADR-007 choice. A *partially* configured backup is still
  // treated as a misconfiguration, same reasoning as the primary.
  const backup = resolveOperatorIdentity(
    process.env.BACKUP_APPROVER_USERNAME,
    process.env.BACKUP_APPROVER_PASSWORD_HASH,
    process.env.BACKUP_APPROVER_TOTP_SECRET,
  );
  if (!sessionConfig || primary === null || primary === "misconfigured" || backup === "misconfigured") {
    res.status(503).json({
      error:
        "authentication is not configured — set ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_TOTP_SECRET, and SESSION_SIGNING_SECRET " +
        "(BACKUP_APPROVER_USERNAME/_PASSWORD_HASH/_TOTP_SECRET are optional, but must be all set together if used)",
    });
    return;
  }
  const { username, password, totpCode } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string" || typeof totpCode !== "string") {
    res.status(400).json({ error: "username (string), password (string), and totpCode (string) are required" });
    return;
  }
  // ADR-019: matching now runs against one or two configured identities —
  // see operatorDirectory.ts for the short-circuit and anti-enumeration
  // reasoning this preserves from the single-operator version.
  const identities: OperatorIdentity[] = backup ? [primary, backup] : [primary];
  const matched = await findAuthenticatedOperator(identities, username, password, totpCode);
  if (!matched) {
    auditLog.record({ subject: username, action: "login", decision: "denied", reasonCode: "invalid_credentials" });
    // Deliberately the same generic message whether the username, password,
    // or TOTP code was wrong, and regardless of which identity (if either)
    // partially matched — naming any of that would let a caller probe
    // factors, or the existence of a second identity, separately.
    res.status(401).json({ error: "invalid username, password, or authentication code" });
    return;
  }
  auditLog.record({ subject: matched.username, action: "login", decision: "allowed" });
  const token = createSessionToken(matched.username, sessionConfig);
  res.status(200).json({ token });
});

// Shared by every route that reads an `Authorization: Bearer <...>` header
// — requireSession, requireAgentCredential, and the token-secret routes
// below all did this same two-line extraction independently before this
// was lifted out (three call sites is this codebase's own stated threshold
// for "not a coincidence," per CLAUDE.md's Composition Rules).
function bearerToken(req: express.Request): string {
  const header = req.header("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
}

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
  const token = bearerToken(req);
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

// ADR-009 hardening: an operator (already authenticated via requireSession)
// registers a known agent. The credential is returned exactly once, here —
// never retrievable again, only its hash is stored.
app.post("/agent-identities", requireSession, async (req, res) => {
  const { subject } = req.body ?? {};
  if (typeof subject !== "string") {
    res.status(400).json({ error: "subject (string) is required" });
    return;
  }
  try {
    const { identity, credential } = await registerAgentIdentity(
      { subject },
      req.session!.username,
      agentIdentityStore,
      auditLog,
    );
    res.status(201).json({ id: identity.id, subject: identity.subject, credential });
  } catch (err) {
    if (err instanceof InvalidAgentIdentityError || err instanceof DuplicateAgentIdentityError) {
      res.status(400).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// Metadata only — never the credential itself, which was never stored raw
// in the first place.
app.get("/agent-identities", requireSession, (_req, res) => {
  res.json(agentIdentityStore.list().map((i) => ({ id: i.id, subject: i.subject, createdBy: i.createdBy, createdAt: i.createdAt })));
});

// ADR-009 hardening: applied to POST /requests below. Closes requester-
// identity spoofing — "subject" is derived from a real, pre-registered
// credential, never something the caller types into the request body.
// Never throws; a missing/invalid/unrecognized credential is a clean 401.
async function requireAgentCredential(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
  const credential = bearerToken(req);
  if (!credential) {
    res.status(401).json({ error: "missing Authorization: Bearer <agentId>.<secret> header" });
    return;
  }
  const identity = await authenticateAgent(credential, agentIdentityStore);
  if (!identity) {
    res.status(401).json({ error: "invalid agent credential" });
    return;
  }
  req.agentIdentity = { subject: identity.subject };
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
// ADR-009 hardening: requires a real agent credential — subject comes from
// req.agentIdentity, never from the request body. A subject field in the
// body is silently ignored, same treatment as policyId above.
app.post("/requests", requireAgentCredential, (req, res) => {
  const { scope, ttlSeconds, idempotencyKey } = req.body ?? {};
  if (!Array.isArray(scope) || typeof ttlSeconds !== "number") {
    res.status(400).json({ error: "scope (string[]) and ttlSeconds (number) are required" });
    return;
  }
  const pending = requestToken(
    {
      subject: req.agentIdentity!.subject,
      scope,
      ttlSeconds,
      idempotencyKey: typeof idempotencyKey === "string" ? idempotencyKey : undefined,
    },
    requestStore,
    anomalyDetector,
    auditLog,
    // ADR-019: whoever's configured as the primary approver right now
    // becomes this request's assigned decider — read fresh per request,
    // not cached, matching every other auth-config read in this file.
    process.env.ADMIN_USERNAME,
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
  // ADR-013: this route is unauthenticated — tokenSecret must never appear
  // here even transiently, or the whole point of claiming it through a
  // dedicated, authenticated, one-time route is defeated.
  const { tokenSecret: _tokenSecret, ...safe } = pending;
  res.json(safe);
});

// ADR-013: the one legitimate path a real caller uses to actually receive
// a token's secret. Requires the same agent credential used to submit the
// original request — claimTokenSecret() checks the derived subject
// matches, not anything this call could just claim in its body.
app.post<{ id: string }>("/requests/:id/token-secret", requireAgentCredential, (req, res) => {
  try {
    const claimed = claimTokenSecret(req.params.id, req.agentIdentity!.subject, requestStore, auditLog);
    res.status(200).json(claimed);
  } catch (err) {
    if (err instanceof UnknownRequestError) {
      res.status(404).json({ error: err.message });
    } else if (err instanceof WrongSubjectError) {
      res.status(403).json({ error: err.message });
    } else if (err instanceof RequestNotApprovedError) {
      res.status(409).json({ error: err.message });
    } else if (err instanceof TokenSecretAlreadyClaimedError) {
      res.status(410).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// ADR-019: checked immediately before an approve/deny attempt runs — no
// scheduler exists in this system, so this is the only point escalation
// can happen. Thresholds read fresh per request, same treatment as every
// other env-sourced config in this file; a real production default (15
// minutes) that's overridable for fast verification, unlike CoreOps's own
// deliberately-fixed 15-minute window — a coding agent verifying this live
// can't usefully sit idle for 15 real minutes the way a human demo can.
function checkThisRequestTimeout(requestId: string): void {
  checkRequestTimeout(
    requestId,
    requestStore,
    auditLog,
    envNumber("REQUEST_DECISION_WINDOW_MS") ?? 15 * 60_000,
    process.env.BACKUP_APPROVER_USERNAME,
  );
}

// ADR-009 hardening: approver is now the authenticated session's own
// username — never something the caller types into the request body.
// ADR-010: policyId is still the approver's own choice, made at approval
// time — not inherited from anything the requester submitted.
app.post<{ id: string }>("/requests/:id/approve", requireSession, async (req, res) => {
  const approver = req.session!.username;
  const policyId = req.body?.policyId;
  try {
    checkThisRequestTimeout(req.params.id);
    const token = await approveRequest(
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
    } else if (err instanceof UnauthorizedDeciderError) {
      res.status(403).json({ error: err.message });
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
    checkThisRequestTimeout(req.params.id);
    denyRequest(req.params.id, requestStore, auditLog, approver, reasonCode);
    res.status(204).end();
  } catch (err) {
    if (err instanceof UnknownRequestError) {
      res.status(404).json({ error: err.message });
    } else if (err instanceof RequestNotPendingError) {
      res.status(409).json({ error: err.message });
    } else if (err instanceof UnauthorizedDeciderError) {
      res.status(403).json({ error: err.message });
    } else {
      throw err;
    }
  }
});

// ADR-013: secretHash is an implementation detail of the possession check
// — it must never leave the server, same discipline GET /agent-identities
// already holds for agent credentials. Applied everywhere a raw Token
// object gets serialized: approve's response, revoke's, GET /tokens, and
// delegate's decision.token below.
function withoutSecretHash(token: Token): Omit<Token, "secretHash"> {
  const { secretHash: _secretHash, ...rest } = token;
  return rest;
}

// The Enforcement Gateway (REQ-004), reachable for real — this is what
// STORY-001/002 were missing a demo path for.
// ADR-013: possession-checked — the caller must present the secret handed
// out at issuance (or claimed via POST /requests/:id/token-secret), not
// just know the token's public id.
app.post("/tokens/:id/enforce", async (req, res) => {
  const action = req.body?.action;
  if (typeof action !== "string") {
    res.status(400).json({ error: "action (string) is required" });
    return;
  }
  const decision = await enforceToken(req.params.id, bearerToken(req), action, tokenStore, auditLog);
  res.status(200).json(decision);
});

// Deliberately NOT possession-checked — revocation is a management action
// (an operator revoking a leaked or no-longer-needed credential, possibly
// one they no longer hold the secret for), not a use of the token's own
// authority. ADR-015 (Control hardening): now requires a real operator
// session instead of being fully open — the actor recorded on the
// revocation (and every cascaded child revocation it triggers) comes from
// that session, never a client-supplied field.
app.post<{ id: string }>("/tokens/:id/revoke", requireSession, (req, res) => {
  const reasonCode = req.body?.reasonCode as RevocationReason | undefined;
  const valid: RevocationReason[] = ["compromised", "no_longer_needed", "policy_violation", "superseded"];
  if (!reasonCode || !valid.includes(reasonCode)) {
    res.status(400).json({ error: `reasonCode must be one of: ${valid.join(", ")}` });
    return;
  }
  try {
    const token = revokeToken(req.params.id, tokenStore, auditLog, reasonCode, undefined, req.session!.username);
    res.status(200).json(withoutSecretHash(token));
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
// ADR-013: possession-checked against the PARENT token — delegating spends
// some of the parent's authority, so minting a child from it requires the
// same proof using it directly would. On success, the child's own secret
// is returned here, once, synchronously — whoever proved they hold the
// parent is the rightful holder of what's minted from it.
app.post("/tokens/:id/delegate", async (req, res) => {
  const { subject, scope, ttlSeconds } = req.body ?? {};
  if (typeof subject !== "string" || !Array.isArray(scope) || typeof ttlSeconds !== "number") {
    res.status(400).json({ error: "subject (string), scope (string[]), and ttlSeconds (number) are required" });
    return;
  }
  const decision = await delegateToken(req.params.id, bearerToken(req), subject, scope, ttlSeconds, tokenStore, auditLog);
  res.status(200).json(decision.approved ? { ...decision, token: withoutSecretHash(decision.token) } : decision);
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
  const result = await accessMockEndpoint(req.params.id, bearerToken(req), system, verb, tokenStore, auditLog, mockEndpoints, accessConfig);
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
// ADR-013: secretHash never leaves the server, even here — listing a
// token's metadata is not the same as being able to use it.
app.get("/tokens", (_req, res) => {
  res.json(tokenStore.list().map(withoutSecretHash));
});

// REQ-011/REQ-017: human-authored policies. PATCH, not PUT — a policy
// modification is a partial change (name/allowedScope/maxTtlSeconds
// individually), not a full replacement.
// ADR-015 (Control hardening): requires a real operator session — authoredBy
// is derived from it, same treatment ADR-011 gave approver and ADR-012 gave
// subject. A client-supplied authoredBy in the body is silently ignored.
app.post("/policies", requireSession, (req, res) => {
  const { name, allowedScope, maxTtlSeconds } = req.body ?? {};
  if (typeof name !== "string" || !Array.isArray(allowedScope) || typeof maxTtlSeconds !== "number") {
    res.status(400).json({ error: "name (string), allowedScope (string[]), and maxTtlSeconds (number) are required" });
    return;
  }
  try {
    const policy = createPolicy({ name, allowedScope, maxTtlSeconds }, req.session!.username, policyStore, auditLog);
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

app.patch<{ id: string }>("/policies/:id", requireSession, (req, res) => {
  const { name, allowedScope, maxTtlSeconds } = req.body ?? {};
  try {
    const policy = modifyPolicy(
      req.params.id,
      {
        name: typeof name === "string" ? name : undefined,
        allowedScope: Array.isArray(allowedScope) ? allowedScope : undefined,
        maxTtlSeconds: typeof maxTtlSeconds === "number" ? maxTtlSeconds : undefined,
      },
      req.session!.username,
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
// ADR-015 (Control hardening): requires a real operator session — this is
// the route that defines what counts as sensitive customer data, so who
// can define it matters at least as much as who can create a policy.
app.post("/redaction-rules", requireSession, (req, res) => {
  const { name, sensitiveFields } = req.body ?? {};
  if (typeof name !== "string" || typeof sensitiveFields !== "object" || sensitiveFields === null || Array.isArray(sensitiveFields)) {
    res.status(400).json({ error: "name (string) and sensitiveFields (object mapping field name to required scope) are required" });
    return;
  }
  try {
    const rule = createRedactionRule({ name, sensitiveFields }, req.session!.username, redactionRuleStore, auditLog);
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
app.post("/tokens/:id/customer-data/:customerId", async (req, res) => {
  const result = await accessCustomerData(
    req.params.id,
    bearerToken(req),
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
  // Never swallow an error — log the real one, but don't leak internals to
  // the caller. ADR-020: structured, with a real error class named — the
  // single most valuable of this ADR's three call sites, since this is the
  // one path that catches genuinely unexpected bugs.
  logEvent({
    level: "error",
    event: "unhandled_error",
    context: {
      errorClass: err instanceof Error ? err.constructor.name : "Unknown",
      message: err instanceof Error ? err.message : String(err),
    },
  });
  res.status(500).json({ error: "internal error" });
});

// Only bind a real port when this file is run directly (`npm run start`),
// not when it's imported — the SDK's own tests import `app` and bind it to
// an ephemeral port themselves, to exercise the real HTTP stack without
// colliding with a live dev server on the same fixed port.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 4000;
  const server = app.listen(port, () => {
    logEvent({ level: "info", event: "server_started", context: { port } });
  });

  // Disposability (12-factor): shut down cleanly on SIGTERM rather than being killed hard.
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}

export { app };
