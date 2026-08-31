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
  // ADR-013: the token's plaintext secret, held here transiently between
  // issuance and the one time the rightful requester claims it via
  // claimTokenSecret() below — cleared the instant it's claimed. NEVER
  // send this field over GET /requests/:id (server.ts strips it
  // explicitly) — that route is unauthenticated, and this field existing
  // at all is only safe because nothing public ever reads it back out.
  tokenSecret?: string;
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

// ADR-013: claimTokenSecret()'s three distinct failure shapes — kept
// separate rather than reusing UnknownRequestError/RequestNotPendingError,
// since each maps to a different, deliberate HTTP status at the server.ts
// boundary (403 / 409 / 410) and a caller needs to tell them apart, not
// just learn "it didn't work."
export class WrongSubjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrongSubjectError";
  }
}

export class RequestNotApprovedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestNotApprovedError";
  }
}

export class TokenSecretAlreadyClaimedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenSecretAlreadyClaimedError";
  }
}

// REQ-016: every submission is checked for anomalies automatically, here —
// not as a separate step a caller could forget to call. The anomaly check
// only writes an audit entry when something actually fires; a normal request
// produces no *anomaly* entry, matching "no alert is triggered" literally.
// Every submission — anomalous or not — does write one unconditional
// `request_submitted` entry (below), which is what makes SDK/API usage
// genuinely traceable rather than only visible when something goes wrong.
// Deliberately excludes policyId from what a requester can submit — see
// ADR-010. Which policy governs issuance is the approver's decision, made
// at approval time (approveRequest, below), not something a requester
// gets to pre-select for their own request.
export function requestToken(
  request: Omit<TokenRequest, "policyId"> & { idempotencyKey?: string },
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

// ADR-010: policyId is the approver's own choice, supplied here at
// approval time — not read from the pending request. A requester citing
// their own policyId at submission time (the original design) made
// "policy attached" a self-issued rubber stamp: nothing stopped a
// requester from creating a maximally permissive policy and citing it on
// their own request, and the Console had no way to show an approver which
// policy (if any) was actually attached before they clicked Approve.
// policyStore is optional for the same reason issueToken's is: approving
// with no policyId works exactly as it always did.
// ADR-013: returns only the Token, never the secret — the approver isn't
// the token's rightful holder, just the human who authorized it existing.
// The secret is stored transiently on the request record instead (below)
// and only ever leaves the server via claimTokenSecret(), to the original
// requesting subject, exactly once.
export async function approveRequest(
  requestId: string,
  requestStore: RequestStore,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  approver: string,
  policyId?: string,
  policyStore?: PolicyStore,
  now: Date = new Date(),
): Promise<Token> {
  const pending = getPending(requestId, requestStore, "approve");

  let token: Token;
  let secret: string;
  try {
    ({ token, secret } = await issueToken(
      { subject: pending.subject, scope: pending.scope, ttlSeconds: pending.ttlSeconds, policyId },
      tokenStore,
      policyStore,
    ));
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
  requestStore.save({ ...pending, status: "approved", tokenId: token.id, tokenSecret: secret });
  auditLog.record({
    requestId,
    tokenId: token.id,
    // ADR-010: which policy actually governed this issuance is now the
    // approver's own decision — it belongs in the same audit entry as the
    // decision itself, not left implicit. A compliance officer should be
    // able to see this from the trail alone, not have to cross-reference.
    policyId,
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

// ADR-013: the one legitimate path a real caller uses to actually receive
// a token's secret — everything else in this file only ever produces
// hashes and ids. requestingSubject comes from the caller's own verified
// agent credential (server.ts's requireAgentCredential), never from
// anything the caller could just type — matching it against pending.subject
// is what makes this "prove you're the one who asked," not "prove you can
// guess a request id," which is the whole point given GET /requests/:id is
// public and its id alone was never meant to be a bearer credential either.
export function claimTokenSecret(
  requestId: string,
  requestingSubject: string,
  requestStore: RequestStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): { tokenId: string; secret: string } {
  const pending = requestStore.get(requestId);
  if (!pending) {
    throw new UnknownRequestError(`cannot claim a token secret for request "${requestId}" — no such request exists`);
  }
  if (pending.subject !== requestingSubject) {
    auditLog.record({
      requestId,
      subject: requestingSubject,
      action: "claim_token_secret",
      decision: "denied",
      reasonCode: "wrong_subject",
      message: `Credential authenticated as "${requestingSubject}", but request "${requestId}" was submitted by "${pending.subject}" — only the original requester can claim its token's secret.`,
    }, now);
    throw new WrongSubjectError(`request "${requestId}" was not submitted by "${requestingSubject}"`);
  }
  if (pending.status !== "approved" || !pending.tokenId) {
    throw new RequestNotApprovedError(`request "${requestId}" is "${pending.status}" — no token has been issued for it yet`);
  }
  if (!pending.tokenSecret) {
    throw new TokenSecretAlreadyClaimedError(`the secret for request "${requestId}"'s token was already claimed once — it cannot be retrieved again`);
  }

  const secret = pending.tokenSecret;
  const tokenId = pending.tokenId;
  // Cleared, not just marked claimed — the plaintext must not still be
  // sitting in the store after this point, same "the secret exists for one
  // response only" guarantee issueToken's own return value makes.
  requestStore.save({ ...pending, tokenSecret: undefined });
  auditLog.record({
    requestId,
    tokenId,
    subject: requestingSubject,
    action: "claim_token_secret",
    decision: "token_secret_claimed",
  }, now);
  return { tokenId, secret };
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
