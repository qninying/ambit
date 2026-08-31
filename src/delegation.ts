// REQ-003/REQ-012: a subagent inherits a STRICT subset of its parent's scope
// — never the same scope, never more. This is the delegation-time half of
// "never broader than parent"; issueToken()'s expiry cap and revokeToken()'s
// cascade are the other two halves, for lifetime and for after-the-fact
// revocation respectively.

import type { AuditLog } from "./auditLog.js";
import { CircuitOpenError } from "./circuitBreaker.js";
import { verifyPassword } from "./passwordHash.js";
import { issueToken, type Token } from "./token.js";
import type { TokenStore } from "./tokenStore.js";

export type DelegationDenialReason =
  | "parent_invalid"
  | "empty_scope"
  | "exceeds_parent_scope"
  | "not_narrower"
  | "store_unavailable"
  | "invalid_credential";

export type DelegationDecision =
  // ADR-013: the child's secret is handed back here, once, synchronously —
  // whoever proved possession of the parent (below) is the rightful holder
  // of the token being minted from it, so there's no separate claim step
  // the way there is for a request going through human approval.
  | { approved: true; token: Token; secret: string }
  | { approved: false; reasonCode: DelegationDenialReason };

// Never throws — same "always a decision" contract as enforceToken, so a
// store outage (REQ-008) is a denial reason like any other, not an
// exception a caller has to separately handle.
//
// ADR-013: providedParentSecret is checked as soon as the parent record is
// found, before any scope/expiry detail is examined — same "prove
// possession before anything else is disclosed" ordering as enforceToken.
export async function delegateToken(
  parentTokenId: string,
  providedParentSecret: string,
  childSubject: string,
  requestedScope: string[],
  ttlSeconds: number,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): Promise<DelegationDecision> {
  let parent;
  try {
    parent = tokenStore.get(parentTokenId);
  } catch (err) {
    if (err instanceof CircuitOpenError) {
      return deny(parentTokenId, childSubject, "store_unavailable", auditLog, now);
    }
    throw err;
  }
  if (!parent) {
    return deny(parentTokenId, childSubject, "parent_invalid", auditLog, now);
  }

  const possessed = await verifyPassword(providedParentSecret, parent.secretHash);
  if (!possessed) {
    return deny(parentTokenId, childSubject, "invalid_credential", auditLog, now);
  }

  const parentValid = parent.status === "active" && now.getTime() < parent.expiresAt.getTime();
  if (!parentValid) {
    return deny(parentTokenId, childSubject, "parent_invalid", auditLog, now);
  }

  if (requestedScope.length === 0) {
    return deny(parentTokenId, childSubject, "empty_scope", auditLog, now);
  }

  const allInParent = requestedScope.every((s) => parent.scope.includes(s));
  if (!allInParent) {
    return deny(parentTokenId, childSubject, "exceeds_parent_scope", auditLog, now);
  }

  // "Strict subset" means requesting the parent's exact scope back is also a
  // denial — that's copying, not narrowing.
  const isProperSubset = parent.scope.some((s) => !requestedScope.includes(s));
  if (!isProperSubset) {
    return deny(parentTokenId, childSubject, "not_narrower", auditLog, now);
  }

  let token: Token;
  let secret: string;
  try {
    ({ token, secret } = await issueToken({ subject: childSubject, scope: requestedScope, ttlSeconds, parentTokenId }, tokenStore));
  } catch (err) {
    if (err instanceof CircuitOpenError) {
      return deny(parentTokenId, childSubject, "store_unavailable", auditLog, now);
    }
    throw err;
  }
  auditLog.record({
    tokenId: token.id,
    subject: childSubject,
    action: "delegate",
    decision: "allowed",
  }, now);
  return { approved: true, token, secret };
}

function deny(
  parentTokenId: string,
  childSubject: string,
  reasonCode: DelegationDenialReason,
  auditLog: AuditLog,
  now: Date,
): DelegationDecision {
  auditLog.record({
    tokenId: parentTokenId,
    subject: childSubject,
    action: "delegate",
    decision: "denied",
    reasonCode,
  }, now);
  return { approved: false, reasonCode };
}
