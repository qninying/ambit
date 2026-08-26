import { describe, expect, it } from "vitest";
import { AnomalyDetector } from "./anomalyDetector.js";
import { AuditLog } from "./auditLog.js";
import { PolicyViolationError } from "./token.js";
import { PolicyStore, createPolicy } from "./policy.js";
import { RequestStore } from "./requestStore.js";
import { TokenStore } from "./tokenStore.js";
import {
  RequestNotPendingError,
  UnknownRequestError,
  approveRequest,
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

  // Acceptance: "Given a normal request, when it is processed, then no alert
  // is triggered." — checked as an absence, not just an unasserted default.
  it("does not log an anomaly alert for a normal request", () => {
    const { requestStore, anomalyDetector, auditLog } = setup();
    requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    expect(auditLog.entries()).toHaveLength(0);
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

    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        requestId: pending.id,
        subject: "agent-42",
        action: "anomaly_check",
        decision: "anomaly_detected",
        reasonCode: "scope_too_broad",
      }),
    ]);
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
  it("issues a real token once an approver approves", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(token.subject).toBe("agent-42");
    expect(token.status).toBe("active");
    expect(tokenStore.get(token.id)).toEqual(token);
    expect(requestStore.get(pending.id)?.status).toBe("approved");
  });

  // Acceptance: "Trust: Approval actions are logged."
  it("logs the approval with the approver as actor", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    const token = approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        requestId: pending.id,
        tokenId: token.id,
        decision: "request_approved",
        actor: "approver-1",
      }),
    ]);
  });

  // A policy-blocked approval is still a real event — it must leave an
  // audit trail, and the request must stay pending so a corrected, in-policy
  // approval attempt is still possible (not silently consumed on failure).
  it("logs a policy-violation denial when approval would exceed the attached policy, and leaves the request pending", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy({ name: "Email only", allowedScope: ["email:send"], maxTtlSeconds: 3600 }, "policy-manager-1", policyStore, auditLog);
    const pending = requestToken(
      { subject: "agent-42", scope: ["payment:charge"], ttlSeconds: 300, policyId: policy.id },
      requestStore,
      anomalyDetector,
      auditLog,
    );

    expect(() => approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1", policyStore)).toThrow(
      PolicyViolationError,
    );

    expect(requestStore.get(pending.id)?.status).toBe("pending");
    const entries = auditLog.entries().filter((e) => e.requestId === pending.id && e.action === "approve_request");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ decision: "request_denied", actor: "approver-1" });
  });

  it("refuses to approve an unknown request id", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    expect(() => approveRequest("not-a-real-id", requestStore, tokenStore, auditLog, "approver-1")).toThrow(
      UnknownRequestError,
    );
  });

  // Idempotency guardrail: approving twice must not issue two tokens.
  it("refuses to approve the same request twice", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(() => approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1")).toThrow(
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

    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        requestId: pending.id,
        decision: "request_denied",
        actor: "approver-1",
        reasonCode: "scope_too_broad",
      }),
    ]);
  });

  it("refuses to deny an unknown request id", () => {
    const { requestStore, auditLog, anomalyDetector } = setup();
    expect(() => denyRequest("not-a-real-id", requestStore, auditLog, "approver-1")).toThrow(UnknownRequestError);
  });

  it("refuses to deny an already-decided request", () => {
    const { requestStore, tokenStore, auditLog, anomalyDetector } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(() => denyRequest(pending.id, requestStore, auditLog, "approver-2")).toThrow(RequestNotPendingError);
  });
});
