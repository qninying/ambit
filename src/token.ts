// REQ-001: short-lived, narrowly-scoped tokens for AI agents.
import type { AuditLog } from "./auditLog.js";
import { CircuitOpenError } from "./circuitBreaker.js";
import type { PolicyStore } from "./policy.js";
import type { TokenStore } from "./tokenStore.js";

export interface TokenRequest {
  subject: string;
  scope: string[];
  ttlSeconds: number;
  // Present when this token is delegated from another rather than issued at
  // the root. Opaque to issueToken beyond the expiry cap below — delegateToken
  // owns the scope/validity gatekeeping decision of whether delegation is
  // allowed at all.
  parentTokenId?: string;
  // REQ-011: when set, this issuance is checked against a human-authored
  // policy (policy.ts) — optional so every existing caller (approveRequest,
  // delegateToken) keeps working unchanged with no policy attached.
  policyId?: string;
}

export class PolicyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyViolationError";
  }
}

export interface Token {
  id: string;
  subject: string;
  scope: string[];
  issuedAt: Date;
  expiresAt: Date;
  status: "active" | "revoked";
  parentTokenId?: string;
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
export function issueToken(request: TokenRequest, store: TokenStore, policyStore?: PolicyStore): Token {
  if (request.scope.length === 0) {
    throw new InvalidScopeError("scope must include at least one permission");
  }
  if (request.ttlSeconds <= 0) {
    throw new InvalidScopeError("ttlSeconds must be positive — a token cannot be issued already expired");
  }

  // "Given a policy, when it is modified, then changes are applied" is true
  // BECAUSE this looks the policy up fresh by id on every issuance, same
  // fresh-lookup pattern as TokenStore/RequestStore — not because anything
  // here caches or assumes the policy hasn't changed since last checked.
  if (request.policyId) {
    if (!policyStore) {
      throw new PolicyViolationError(`policyId "${request.policyId}" given but no PolicyStore was provided to check against`);
    }
    const policy = policyStore.get(request.policyId);
    if (!policy) {
      throw new PolicyViolationError(`unknown policy "${request.policyId}"`);
    }
    const withinScope = request.scope.every((s) => policy.allowedScope.includes(s));
    if (!withinScope) {
      throw new PolicyViolationError(`requested scope exceeds policy "${policy.name}"`);
    }
    if (request.ttlSeconds > policy.maxTtlSeconds) {
      throw new PolicyViolationError(`requested ttlSeconds (${request.ttlSeconds}) exceeds policy "${policy.name}"'s max of ${policy.maxTtlSeconds}`);
    }
  }

  const issuedAt = new Date();
  let expiresAt = new Date(issuedAt.getTime() + request.ttlSeconds * 1000);

  // A delegated token can never outlive the credential it was derived from —
  // enforced here, unconditionally, so this can't be bypassed by a caller
  // that forgets to check it. REQ-012's "never broader than parent" applies
  // to lifetime as much as it does to scope.
  if (request.parentTokenId) {
    const parent = store.get(request.parentTokenId);
    if (parent && expiresAt.getTime() > parent.expiresAt.getTime()) {
      expiresAt = parent.expiresAt;
    }
  }

  const token: Token = {
    id: crypto.randomUUID(),
    subject: request.subject,
    scope: request.scope,
    issuedAt,
    expiresAt,
    status: "active",
    parentTokenId: request.parentTokenId,
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
  | { allowed: false; reasonCode: "revoked" | "expired" | "out_of_scope" | "unknown_token" | "store_unavailable" };

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
  let token;
  try {
    token = store.get(tokenId);
  } catch (err) {
    // REQ-008: the store itself is unreachable (circuit open). Same
    // guardrail as unknown_token below — can't confirm validity, so deny,
    // never throw. enforceToken's contract is "always a decision," and a
    // store outage doesn't get to be the exception to that.
    if (err instanceof CircuitOpenError) {
      auditLog.record({ tokenId, subject: "unknown", action, decision: "denied", reasonCode: "store_unavailable" }, now);
      return { allowed: false, reasonCode: "store_unavailable" };
    }
    throw err;
  }
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

  cascadeRevoke(tokenId, store, auditLog, now);
  return revoked;
}

// Revoking a token must revoke everything delegated from it, transitively —
// a sub-subagent's token included, not just direct children. Otherwise a
// subagent keeps working after the credential it was derived from no longer
// does, which is the same class of problem REQ-012 exists to prevent, just
// surfacing at revocation time instead of delegation time.
function cascadeRevoke(parentId: string, store: TokenStore, auditLog: AuditLog, now: Date): void {
  for (const child of store.childrenOf(parentId)) {
    if (child.status !== "active") continue; // already revoked — don't double-log
    const revokedChild: Token = { ...child, status: "revoked" };
    store.save(revokedChild);
    auditLog.record({
      tokenId: child.id,
      subject: child.subject,
      action: "revoke",
      decision: "revoked",
      reasonCode: "parent_revoked",
    }, now);
    cascadeRevoke(child.id, store, auditLog, now);
  }
}
