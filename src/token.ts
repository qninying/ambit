// REQ-001: short-lived, narrowly-scoped tokens for AI agents.
import type { AuditLog } from "./auditLog.js";

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
  status: "active";
}

export class InvalidScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidScopeError";
  }
}

export function issueToken(request: TokenRequest): Token {
  if (request.scope.length === 0) {
    throw new InvalidScopeError("scope must include at least one permission");
  }
  if (request.ttlSeconds <= 0) {
    throw new InvalidScopeError("ttlSeconds must be positive — a token cannot be issued already expired");
  }

  const issuedAt = new Date();
  return {
    id: crypto.randomUUID(),
    subject: request.subject,
    scope: request.scope,
    issuedAt,
    expiresAt: new Date(issuedAt.getTime() + request.ttlSeconds * 1000),
    status: "active",
  };
}

// REQ-004: validate token scope and revocation status in real-time at the
// Enforcement Gateway. REQ-006 (guardrail): deny, never allow, when validity
// or scope cannot be confirmed — every branch below ends in a denial except
// the one that positively confirms both.
export type EnforcementDecision =
  | { allowed: true }
  | { allowed: false; reasonCode: "revoked" | "expired" | "out_of_scope" };

export function enforceToken(
  token: Token,
  action: string,
  auditLog: AuditLog,
  now: Date = new Date(),
): EnforcementDecision {
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
