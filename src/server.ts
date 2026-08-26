// The actual application surface — everything in token.ts/tokenRequest.ts is
// only real, demoable functionality once something can call it. One process,
// one set of in-memory stores for now; a real backing store is a separate
// infrastructure decision, not made here.

import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { AnomalyDetector } from "./anomalyDetector.js";
import { AuditLog } from "./auditLog.js";
import { InvalidScopeError, UnknownTokenError, enforceToken, revokeToken, type RevocationReason } from "./token.js";
import { delegateToken } from "./delegation.js";
import { RequestNotPendingError, UnknownRequestError, approveRequest, denyRequest, requestToken } from "./tokenRequest.js";
import { RequestStore } from "./requestStore.js";
import { TokenStore } from "./tokenStore.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function envNumber(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : undefined;
}

const tokenStore = new TokenStore();
const requestStore = new RequestStore();
const auditLog = new AuditLog();
// Thresholds are a judgment call — overridable without a code change via
// ANOMALY_MAX_SCOPE_BREADTH / ANOMALY_VELOCITY_WINDOW_MS / ANOMALY_MAX_REQUESTS_PER_WINDOW.
const anomalyDetector = new AnomalyDetector({
  maxScopeBreadth: envNumber("ANOMALY_MAX_SCOPE_BREADTH"),
  velocityWindowMs: envNumber("ANOMALY_VELOCITY_WINDOW_MS"),
  maxRequestsPerWindow: envNumber("ANOMALY_MAX_REQUESTS_PER_WINDOW"),
});

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// POST /requests — submit a token request. Sits pending until an approver
// acts on it; no token exists yet.
app.post("/requests", (req, res) => {
  const { subject, scope, ttlSeconds } = req.body ?? {};
  if (typeof subject !== "string" || !Array.isArray(scope) || typeof ttlSeconds !== "number") {
    res.status(400).json({ error: "subject (string), scope (string[]), and ttlSeconds (number) are required" });
    return;
  }
  const pending = requestToken({ subject, scope, ttlSeconds }, requestStore, anomalyDetector, auditLog);
  res.status(201).json(pending);
});

// GET /requests — what the Consent UI actually displays: requests waiting
// on a human decision.
app.get("/requests", (_req, res) => {
  res.json(requestStore.pending());
});

app.post("/requests/:id/approve", (req, res) => {
  const approver = req.body?.approver;
  if (typeof approver !== "string" || approver.length === 0) {
    res.status(400).json({ error: "approver (string) is required" });
    return;
  }
  try {
    const token = approveRequest(req.params.id, requestStore, tokenStore, auditLog, approver);
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

app.post("/requests/:id/deny", (req, res) => {
  const approver = req.body?.approver;
  const reasonCode = req.body?.reasonCode;
  if (typeof approver !== "string" || approver.length === 0) {
    res.status(400).json({ error: "approver (string) is required" });
    return;
  }
  try {
    denyRequest(req.params.id, requestStore, auditLog, approver, typeof reasonCode === "string" ? reasonCode : undefined);
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

app.get("/audit-log", (_req, res) => {
  res.json(auditLog.entries());
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof InvalidScopeError) {
    res.status(400).json({ error: err.message });
    return;
  }
  // Never swallow an error — log the real one, but don't leak internals to the caller.
  console.error(err);
  res.status(500).json({ error: "internal error" });
});

const port = Number(process.env.PORT) || 4000;
const server = app.listen(port, () => {
  console.log(`ambit server listening on :${port}`);
});

// Disposability (12-factor): shut down cleanly on SIGTERM rather than being killed hard.
process.on("SIGTERM", () => server.close(() => process.exit(0)));
