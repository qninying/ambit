// REQ-001: short-lived, narrowly-scoped tokens for AI agents.
import type { AuditLog } from "./auditLog.js";
import type { TokenStore } from "./tokenStore.js";

export interface TokenRequest {
  subject: string;
  scope: string[];
  ttlSeconds: number;
}

export interface Token {
  id: string;
  subject: string;
  scope: string[];
  issuedAt: Date;
  expiresAt: Date;
  status: "active" | "revoked";
}

export class InvalidScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidScopeError";
  }
}

export class UnknownTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnknownTokenError";
  }
}

// Issuing a token means it's real from this point on — the store is what
// enforceToken and revokeToken check against later, not this return value.
// The caller still gets the Token back (e.g. to hand to whoever asked for it).
export function issueToken(request: TokenRequest, store: TokenStore): Token {
  if (request.scope.length === 0) {
    throw new InvalidScopeError("scope must include at least one permission");
  }
  if (request.ttlSeconds <= 0) {
    throw new InvalidScopeError("ttlSeconds must be positive — a token cannot be issued already expired");
  }

  const issuedAt = new Date();
  const token: Token = {
    id: crypto.randomUUID(),
    subject: request.subject,
    scope: request.scope,
    issuedAt,
    expiresAt: new Date(issuedAt.getTime() + request.ttlSeconds * 1000),
    status: "active",
  };
  store.save(token);
  return token;
}

// REQ-004: validate token scope and revocation status in real-time at the
// Enforcement Gateway. REQ-006 (guardrail): deny, never allow, when validity
// or scope cannot be confirmed — every branch below ends in a denial except
// the one that positively confirms all three.
export type EnforcementDecision =
  | { allowed: true }
  | { allowed: false; reasonCode: "revoked" | "expired" | "out_of_scope" | "unknown_token" };

// Takes an id, not a Token — every call re-reads current state from the
// store, so a revocation that happened a moment ago is guaranteed to be seen
// on this call. Passing a Token object here would let a caller re-check a
// stale copy and get a stale answer, which defeats the point of REQ-015.
export function enforceToken(
  tokenId: string,
  action: string,
  store: TokenStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): EnforcementDecision {
  const token = store.get(tokenId);
  if (!token) {
    // Can't confirm validity at all — the guardrail says deny, not throw.
    auditLog.record({ tokenId, subject: "unknown", action, decision: "denied", reasonCode: "unknown_token" }, now);
    return { allowed: false, reasonCode: "unknown_token" };
  }

  const decision = decide(token, action, now);
  auditLog.record({
    tokenId: token.id,
    subject: token.subject,
    action,
    decision: decision.allowed ? "allowed" : "denied",
    reasonCode: decision.allowed ? undefined : decision.reasonCode,
  }, now);
  return decision;
}

function decide(token: Token, action: string, now: Date): EnforcementDecision {
  if (token.status !== "active") {
    return { allowed: false, reasonCode: "revoked" };
  }
  if (now.getTime() >= token.expiresAt.getTime()) {
    return { allowed: false, reasonCode: "expired" };
  }
  if (!token.scope.includes(action)) {
    return { allowed: false, reasonCode: "out_of_scope" };
  }
  return { allowed: true };
}

// REQ-015 (SAFE guardrail): a revoked token's next call fails within the same
// request cycle. This is where that becomes true: revocation writes straight
// into the store, so the very next enforceToken() lookup by the same id sees
// "revoked" — there's no window where a stale in-flight copy still works.
export type RevocationReason = "compromised" | "no_longer_needed" | "policy_violation" | "superseded";

export function revokeToken(
  tokenId: string,
  store: TokenStore,
  auditLog: AuditLog,
  reasonCode: RevocationReason,
  now: Date = new Date(),
): Token {
  const token = store.get(tokenId);
  if (!token) {
    throw new UnknownTokenError(`cannot revoke token "${tokenId}" — no such token was issued`);
  }

  const revoked: Token = { ...token, status: "revoked" };
  store.save(revoked);
  auditLog.record({
    tokenId,
    subject: token.subject,
    action: "revoke",
    decision: "revoked",
    reasonCode,
  }, now);
  return revoked;
}
