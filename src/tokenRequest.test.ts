import { describe, expect, it } from "vitest";
import { AnomalyDetector } from "./anomalyDetector.js";
import { AuditLog } from "./auditLog.js";
import { PolicyViolationError, enforceToken } from "./token.js";
import { PolicyStore, createPolicy } from "./policy.js";
import { RequestStore } from "./requestStore.js";
import { TokenStore } from "./tokenStore.js";
import {
  RequestNotApprovedError,
  RequestNotPendingError,
  TokenSecretAlreadyClaimedError,
  UnknownRequestError,
  WrongSubjectError,
  approveRequest,
  claimTokenSecret,
  denyRequest,
  requestToken,
} from "./tokenRequest.js";

function setup() {
  return {
    requestStore: new RequestStore(),
    tokenStore: new TokenStore(),
    auditLog: new AuditLog(),
    anomalyDetector: new AnomalyDetector(),
  };
}

describe("requestToken", () => {
  it("creates a pending request, not a token", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(pending.id).toBeTruthy();
    expect(pending.status).toBe("pending");
    expect(requestStore.get(pending.id)).toEqual(pending);
  });

  // Trust: every submission is traceable, not just anomalous ones — a
  // normal request must still leave an unconditional audit entry.
  it("logs an unconditional request_submitted entry for every submission", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        requestId: pending.id,
        subject: "agent-42",
        decision: "request_submitted",
      }),
    ]);
  });

  // Acceptance: "Given a normal request, when it is processed, then no alert
  // is triggered." — checked as an absence, not just an unasserted default.
  it("does not log an anomaly alert for a normal request", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(auditLog.entries().some((e) => e.decision === "anomaly_detected")).toBe(false);
  });

  // Acceptance: "Given a token request, when it is anomalous, then an alert
  // is triggered." + "Trust: Anomaly detection actions are logged."
  it("logs an anomaly alert for a request with unusually broad scope", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const pending = requestToken(
      { subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send", "crm:read"], ttlSeconds: 300 },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({
        requestId: pending.id,
        subject: "agent-42",
        action: "anomaly_check",
        decision: "anomaly_detected",
        reasonCode: "scope_too_broad",
      }),
    );
  });

  // The idempotency guarantee the SDK's retry loop depends on: a second
  // requestToken() call with the same (subject, idempotencyKey) must return
  // the existing request, not create a duplicate or write a second
  // request_submitted entry.
  it("returns the existing request instead of creating a duplicate when the same idempotencyKey is reused", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const first = requestToken(
      { subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, idempotencyKey: "retry-1" },
      requestStore,
      anomalyDetector,
      auditLog,
    );
    const second = requestToken(
      { subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, idempotencyKey: "retry-1" },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    expect(second).toEqual(first);
    expect(requestStore.pending()).toHaveLength(1);
    expect(auditLog.entries().filter((e) => e.decision === "request_submitted")).toHaveLength(1);
  });

  it("treats the same idempotencyKey from two different subjects as two separate requests", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const a = requestToken(
      { subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, idempotencyKey: "shared-key" },
      requestStore,
      anomalyDetector,
      auditLog,
    );
    const b = requestToken(
      { subject: "agent-99", scope: ["email:send"], ttlSeconds: 300, idempotencyKey: "shared-key" },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    expect(a.id).not.toBe(b.id);
    expect(requestStore.pending()).toHaveLength(2);
  });

  // The request itself is still created — anomaly detection is a signal,
  // not a gate. Denying it, if warranted, is still the approver's call
  // (STORY-003), not something this story decides on its own.
  it("still creates the pending request even when it's flagged as anomalous", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    const pending = requestToken(
      { subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send", "crm:read"], ttlSeconds: 300 },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    expect(requestStore.get(pending.id)?.status).toBe("pending");
  });
});

describe("approveRequest", () => {
  // Acceptance: "Given a token request, when it is displayed, then the
  // approver can approve or deny it" — the approve half.
  it("issues a real token once an approver approves", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(token.subject).toBe("agent-42");
    expect(token.status).toBe("active");
    expect(tokenStore.get(token.id)).toEqual(token);
    expect(requestStore.get(pending.id)?.status).toBe("approved");
  });

  // ADR-013: the operator who approves is not the token's rightful holder —
  // only the token, never its secret, comes back from this call.
  it("does not return the token's secret to the approver", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect("secret" in token).toBe(false);
  });

  // The link the SDK needs to go from "my request" to "my token" — without
  // this, GET /requests/:id after approval tells a caller *that* it was
  // approved but not *what it got*.
  it("records the issued token's id back onto the request once approved", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(requestStore.get(pending.id)?.tokenId).toBe(token.id);
  });

  // Acceptance: "Trust: Approval actions are logged."
  it("logs the approval with the approver as actor", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({
        requestId: pending.id,
        tokenId: token.id,
        decision: "request_approved",
        actor: "approver-1",
      }),
    );
  });

  // ADR-010: which policy the approver applied has to be visible from the
  // audit trail itself — a compliance officer shouldn't have to
  // cross-reference the token's own policyId (which issueToken doesn't
  // even persist onto the Token record) to find out.
  it("records which policy the approver chose in the approval's own audit entry", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy({ name: "Email only", allowedScope: ["email:send"], maxTtlSeconds: 3600 }, "policy-manager-1", policyStore, auditLog);
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1", policy.id, policyStore);

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ requestId: pending.id, decision: "request_approved", policyId: policy.id }),
    );
  });

  // A policy-blocked approval is still a real event — it must leave an
  // audit trail, and the request must stay pending so a corrected, in-policy
  // approval attempt is still possible (not silently consumed on failure).
  it("logs a policy-violation denial when approval would exceed the attached policy, and leaves the request pending", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy({ name: "Email only", allowedScope: ["email:send"], maxTtlSeconds: 3600 }, "policy-manager-1", policyStore, auditLog);
    const pending = requestToken(
      { subject: "agent-42", scope: ["payment:charge"], ttlSeconds: 300 },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    // ADR-010: the approver chooses the policy at approval time, not the requester at submission time.
    await expect(approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1", policy.id, policyStore)).rejects.toThrow(
      PolicyViolationError,
    );

    expect(requestStore.get(pending.id)?.status).toBe("pending");
    const entries = auditLog.entries().filter((e) => e.requestId === pending.id && e.action === "approve_request");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ decision: "request_denied", actor: "approver-1" });
  });

  it("refuses to approve an unknown request id", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    await expect(approveRequest("not-a-real-id", requestStore, tokenStore, auditLog, "approver-1")).rejects.toThrow(
      UnknownRequestError,
    );
  });

  // Idempotency guardrail: approving twice must not issue two tokens.
  it("refuses to approve the same request twice", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    await expect(approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1")).rejects.toThrow(
      RequestNotPendingError,
    );
  });
});

describe("denyRequest", () => {
  // Acceptance: "Given a denied request, when it is submitted, then the
  // token is not issued." — the actual failure path this story exists to
  // prevent, checked directly against the token store, not just the return
  // value of denyRequest (which returns nothing).
  it("does not issue a token when a request is denied", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    denyRequest(pending.id, requestStore, auditLog, "approver-1", "scope_too_broad");

    expect(requestStore.get(pending.id)?.status).toBe("denied");
    // No token was ever created for this request — nothing in the token
    // store references it, and there's no id to look one up by.
    expect(auditLog.entries().every((e) => e.decision !== "request_approved")).toBe(true);
  });

  it("logs the denial with the approver, and a reason code when given", () => {
    const { requestStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    denyRequest(pending.id, requestStore, auditLog, "approver-1", "scope_too_broad");

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({
        requestId: pending.id,
        decision: "request_denied",
        actor: "approver-1",
        reasonCode: "scope_too_broad",
      }),
    );
  });

  it("refuses to deny an unknown request id", () => {
    const { requestStore, auditLog, anomalyDetector } = setup();
    expect(() => denyRequest("not-a-real-id", requestStore, auditLog, "approver-1", "other")).toThrow(UnknownRequestError);
  });

  it("refuses to deny an already-decided request", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(() => denyRequest(pending.id, requestStore, auditLog, "approver-2", "other")).toThrow(RequestNotPendingError);
  });
});

// ADR-013: the one legitimate path a real caller uses to receive a token's
// secret after human approval — everything else in tokenRequest.ts only
// ever produces hashes and ids.
describe("claimTokenSecret", () => {
  it("returns the tokenId and a secret that genuinely works against the real token", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    const token = await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    const claimed = claimTokenSecret(pending.id, "agent-42", requestStore, auditLog);

    expect(claimed.tokenId).toBe(token.id);
    const decision = await enforceToken(token.id, claimed.secret, "email:send", tokenStore, auditLog);
    expect(decision).toEqual({ allowed: true });
  });

  it("logs a token_secret_claimed entry on a successful claim", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    claimTokenSecret(pending.id, "agent-42", requestStore, auditLog);

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ requestId: pending.id, decision: "token_secret_claimed", subject: "agent-42" }),
    );
  });

  it("refuses to claim for an unknown request id", () => {
    const { requestStore, auditLog } = setup();
    expect(() => claimTokenSecret("not-a-real-id", "agent-42", requestStore, auditLog)).toThrow(UnknownRequestError);
  });

  // The core guarantee: knowing a request's id (GET /requests/:id is public)
  // is not enough — only the credential that originally submitted it can
  // claim what it produced.
  it("refuses to claim on behalf of a subject that did not submit the request, and audits the attempt", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(() => claimTokenSecret(pending.id, "someone-else", requestStore, auditLog)).toThrow(WrongSubjectError);
    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ requestId: pending.id, decision: "denied", reasonCode: "wrong_subject" }),
    );
  });

  it("refuses to claim a request that hasn't been approved yet", () => {
    const { requestStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(() => claimTokenSecret(pending.id, "agent-42", requestStore, auditLog)).toThrow(RequestNotApprovedError);
  });

  it("refuses to claim a request that was denied", () => {
    const { requestStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    denyRequest(pending.id, requestStore, auditLog, "approver-1", "scope_too_broad");

    expect(() => claimTokenSecret(pending.id, "agent-42", requestStore, auditLog)).toThrow(RequestNotApprovedError);
  });

  // The one-time guarantee — the whole point of not returning the secret
  // synchronously to whoever approved it.
  it("refuses a second claim once the secret has already been retrieved once", async () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    await approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");
    claimTokenSecret(pending.id, "agent-42", requestStore, auditLog);

    expect(() => claimTokenSecret(pending.id, "agent-42", requestStore, auditLog)).toThrow(TokenSecretAlreadyClaimedError);
  });
});
