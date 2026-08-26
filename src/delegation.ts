// REQ-003/REQ-012: a subagent inherits a STRICT subset of its parent's scope
// — never the same scope, never more. This is the delegation-time half of
// "never broader than parent"; issueToken()'s expiry cap and revokeToken()'s
// cascade are the other two halves, for lifetime and for after-the-fact
// revocation respectively.

import type { AuditLog } from "./auditLog.js";
import { issueToken, type Token } from "./token.js";
import type { TokenStore } from "./tokenStore.js";

export type DelegationDenialReason = "parent_invalid" | "empty_scope" | "exceeds_parent_scope" | "not_narrower";

export type DelegationDecision =
  | { approved: true; token: Token }
  | { approved: false; reasonCode: DelegationDenialReason };

export function delegateToken(
  parentTokenId: string,
  childSubject: string,
  requestedScope: string[],
  ttlSeconds: number,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): DelegationDecision {
  const parent = tokenStore.get(parentTokenId);
  const parentValid = !!parent && parent.status === "active" && now.getTime() < parent.expiresAt.getTime();
  if (!parent || !parentValid) {
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

  const token = issueToken({ subject: childSubject, scope: requestedScope, ttlSeconds, parentTokenId }, tokenStore);
  auditLog.record({
    tokenId: token.id,
    subject: childSubject,
    action: "delegate",
    decision: "allowed",
  }, now);
  return { approved: true, token };
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
