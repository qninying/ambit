import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
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
  return { requestStore: new RequestStore(), tokenStore: new TokenStore(), auditLog: new AuditLog() };
}

describe("requestToken", () => {
  it("creates a pending request, not a token", () => {
    const { requestStore } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);

    expect(pending.id).toBeTruthy();
    expect(pending.status).toBe("pending");
    expect(requestStore.get(pending.id)).toEqual(pending);
  });
});

describe("approveRequest", () => {
  // Acceptance: "Given a token request, when it is displayed, then the
  // approver can approve or deny it" — the approve half.
  it("issues a real token once an approver approves", () => {
    const { requestStore, tokenStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);

    const token = approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(token.subject).toBe("agent-42");
    expect(token.status).toBe("active");
    expect(tokenStore.get(token.id)).toEqual(token);
    expect(requestStore.get(pending.id)?.status).toBe("approved");
  });

  // Acceptance: "Trust: Approval actions are logged."
  it("logs the approval with the approver as actor", () => {
    const { requestStore, tokenStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);

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

  it("refuses to approve an unknown request id", () => {
    const { requestStore, tokenStore, auditLog } = setup();
    expect(() => approveRequest("not-a-real-id", requestStore, tokenStore, auditLog, "approver-1")).toThrow(
      UnknownRequestError,
    );
  });

  // Idempotency guardrail: approving twice must not issue two tokens.
  it("refuses to approve the same request twice", () => {
    const { requestStore, tokenStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);
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
    const { requestStore, tokenStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);

    denyRequest(pending.id, requestStore, auditLog, "approver-1", "scope_too_broad");

    expect(requestStore.get(pending.id)?.status).toBe("denied");
    // No token was ever created for this request — nothing in the token
    // store references it, and there's no id to look one up by.
    expect(auditLog.entries().every((e) => e.decision !== "request_approved")).toBe(true);
  });

  it("logs the denial with the approver, and a reason code when given", () => {
    const { requestStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);

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
    const { requestStore, auditLog } = setup();
    expect(() => denyRequest("not-a-real-id", requestStore, auditLog, "approver-1")).toThrow(UnknownRequestError);
  });

  it("refuses to deny an already-decided request", () => {
    const { requestStore, tokenStore, auditLog } = setup();
    const pending = requestToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, requestStore);
    approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1");

    expect(() => denyRequest(pending.id, requestStore, auditLog, "approver-2")).toThrow(RequestNotPendingError);
  });
});
