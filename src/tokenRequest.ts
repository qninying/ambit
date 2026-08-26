// REQ-002/REQ-013: human approval for every token request, via a request
// that sits pending until an approver acts on it — issueToken() from
// STORY-001 stays the "a token is now real" primitive; nothing here bypasses
// it. Approval calls it; denial never does.

import type { AuditLog } from "./auditLog.js";
import { issueToken, type Token, type TokenRequest } from "./token.js";
import type { TokenStore } from "./tokenStore.js";
import type { RequestStore } from "./requestStore.js";

export interface PendingRequest extends TokenRequest {
  id: string;
  status: "pending" | "approved" | "denied";
  requestedAt: Date;
}

export class UnknownRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnknownRequestError";
  }
}

// Guards the idempotency requirement from CLAUDE.md: approving (or denying)
// the same request twice must not double-issue a token or double-log a
// decision. A request that's already been decided refuses a second decision
// rather than silently repeating it.
export class RequestNotPendingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestNotPendingError";
  }
}

export function requestToken(request: TokenRequest, requestStore: RequestStore): PendingRequest {
  const pending: PendingRequest = {
    ...request,
    id: crypto.randomUUID(),
    status: "pending",
    requestedAt: new Date(),
  };
  requestStore.save(pending);
  return pending;
}

export function approveRequest(
  requestId: string,
  requestStore: RequestStore,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  approver: string,
  now: Date = new Date(),
): Token {
  const pending = getPending(requestId, requestStore, "approve");

  const token = issueToken({ subject: pending.subject, scope: pending.scope, ttlSeconds: pending.ttlSeconds }, tokenStore);
  requestStore.save({ ...pending, status: "approved" });
  auditLog.record({
    requestId,
    tokenId: token.id,
    subject: pending.subject,
    action: "approve_request",
    decision: "request_approved",
    actor: approver,
  }, now);
  return token;
}

export function denyRequest(
  requestId: string,
  requestStore: RequestStore,
  auditLog: AuditLog,
  approver: string,
  reasonCode?: string,
  now: Date = new Date(),
): void {
  const pending = getPending(requestId, requestStore, "deny");

  requestStore.save({ ...pending, status: "denied" });
  auditLog.record({
    requestId,
    subject: pending.subject,
    action: "deny_request",
    decision: "request_denied",
    actor: approver,
    reasonCode,
  }, now);
}

function getPending(requestId: string, requestStore: RequestStore, verb: "approve" | "deny"): PendingRequest {
  const pending = requestStore.get(requestId);
  if (!pending) {
    throw new UnknownRequestError(`cannot ${verb} request "${requestId}" — no such request exists`);
  }
  if (pending.status !== "pending") {
    throw new RequestNotPendingError(`request "${requestId}" is already ${pending.status}`);
  }
  return pending;
}
