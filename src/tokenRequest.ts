// REQ-002/REQ-013: human approval for every token request, via a request
// that sits pending until an approver acts on it — issueToken() from
// STORY-001 stays the "a token is now real" primitive; nothing here bypasses
// it. Approval calls it; denial never does.

import type { AnomalyDetector } from "./anomalyDetector.js";
import type { AuditLog } from "./auditLog.js";
import { CircuitOpenError } from "./circuitBreaker.js";
import { InvalidScopeError, PolicyViolationError, issueToken, type Token, type TokenRequest } from "./token.js";
import type { TokenStore } from "./tokenStore.js";
import type { RequestStore } from "./requestStore.js";
import type { PolicyStore } from "./policy.js";

export interface PendingRequest extends TokenRequest {
  id: string;
  status: "pending" | "approved" | "denied";
  requestedAt: Date;
  // Set once approveRequest() actually issues a token — the link a caller
  // (the SDK, in particular) needs to go from "my request" to "my token"
  // without a separate lookup path existing for that purpose.
  tokenId?: string;
  // Optional, caller-supplied. Lets requestToken() be safely retried (e.g.
  // by the SDK's timeout-and-retry wrapper) without risking a duplicate
  // pending request — see the idempotency check in requestToken() below.
  idempotencyKey?: string;
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

// REQ-016: every submission is checked for anomalies automatically, here —
// not as a separate step a caller could forget to call. The anomaly check
// only writes an audit entry when something actually fires; a normal request
// produces no *anomaly* entry, matching "no alert is triggered" literally.
// Every submission — anomalous or not — does write one unconditional
// `request_submitted` entry (below), which is what makes SDK/API usage
// genuinely traceable rather than only visible when something goes wrong.
export function requestToken(
  request: TokenRequest & { idempotencyKey?: string },
  requestStore: RequestStore,
  anomalyDetector: AnomalyDetector,
  auditLog: AuditLog,
  now: Date = new Date(),
): PendingRequest {
  // Idempotency: a caller that retried the same (subject, idempotencyKey)
  // pair — e.g. the SDK's timeout-and-retry wrapper, after a response was
  // lost in flight — gets the request that already exists, not a second
  // one. No new store entry, no second audit entry.
  if (request.idempotencyKey) {
    const existing = requestStore.findByIdempotencyKey(request.subject, request.idempotencyKey);
    if (existing) return existing;
  }

  const pending: PendingRequest = {
    ...request,
    id: crypto.randomUUID(),
    status: "pending",
    requestedAt: now,
  };
  requestStore.save(pending);

  auditLog.record({
    requestId: pending.id,
    subject: request.subject,
    action: "request_token",
    decision: "request_submitted",
  }, now);

  const anomaly = anomalyDetector.check(request.subject, request.scope, now);
  if (anomaly.anomalous) {
    auditLog.record({
      requestId: pending.id,
      subject: request.subject,
      action: "anomaly_check",
      decision: "anomaly_detected",
      reasonCode: anomaly.signals.join(","),
    }, now);
  }

  return pending;
}

// policyStore is optional for the same reason issueToken's is: a request
// that never named a policyId works exactly as before. One that did — set
// by whoever submitted it via requestToken() — gets checked against it here,
// at approval time, which is also where issueToken() actually runs.
export function approveRequest(
  requestId: string,
  requestStore: RequestStore,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  approver: string,
  policyStore?: PolicyStore,
  now: Date = new Date(),
): Token {
  const pending = getPending(requestId, requestStore, "approve");

  let token: Token;
  try {
    token = issueToken(
      { subject: pending.subject, scope: pending.scope, ttlSeconds: pending.ttlSeconds, policyId: pending.policyId },
      tokenStore,
      policyStore,
    );
  } catch (err) {
    // An approval attempt that a policy blocks — or that a store outage
    // (REQ-008) interrupts — is still a real event — an administrator
    // investigating "why wasn't this approved" needs to find it here, not
    // discover the audit log has nothing to say about it. The request stays
    // pending (not consumed), so a second attempt, once in-policy or once
    // the store recovers, is still possible.
    if (err instanceof PolicyViolationError || err instanceof InvalidScopeError || err instanceof CircuitOpenError) {
      auditLog.record({
        requestId,
        subject: pending.subject,
        action: "approve_request",
        decision: "request_denied",
        actor: approver,
        reasonCode: err.message,
      }, now);
    }
    throw err;
  }
  requestStore.save({ ...pending, status: "approved", tokenId: token.id });
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

// REQ-010: a closed, distinct set — not a free-form string an approver
// could phrase five different ways for the same underlying reason, which
// would defeat "distinct reason codes" in practice even if a value is
// always present. Same closed-union treatment as RevocationReason.
export type DenialReason = "scope_too_broad" | "policy_violation" | "unverified_subject" | "duplicate_request" | "other";

export function denyRequest(
  requestId: string,
  requestStore: RequestStore,
  auditLog: AuditLog,
  approver: string,
  // REQ-010: required, not optional — a denial with no recorded reason is
  // exactly the "reason code not assigned" failure path this story exists
  // to close. AuditLog.record() also refuses a reasonCode-less denial as a
  // second, structural line of defense (see auditLog.ts).
  reasonCode: DenialReason,
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
