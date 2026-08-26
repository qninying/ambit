import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { InvalidScopeError, PolicyViolationError, enforceToken, issueToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { PolicyStore, createPolicy, modifyPolicy } from "./policy.js";

function setup() {
  return { store: new TokenStore(), auditLog: new AuditLog() };
}

describe("issueToken", () => {
  it("issues an active token scoped and expiring as requested", () => {
    const { store } = setup();
    const before = Date.now();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    const after = Date.now();

    expect(token.id).toBeTruthy();
    expect(token.subject).toBe("agent-42");
    expect(token.scope).toEqual(["email:send"]);
    expect(token.status).toBe("active");
    expect(token.issuedAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(token.issuedAt.getTime()).toBeLessThanOrEqual(after);
    expect(token.expiresAt.getTime() - token.issuedAt.getTime()).toBe(300_000);
  });

  it("saves the issued token in the store, so it can be enforced against later", () => {
    const { store } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    expect(store.get(token.id)).toEqual(token);
  });

  // Failure path: "Token issuance fails due to invalid scope."
  it("refuses to issue a token with an empty scope", () => {
    const { store } = setup();
    expect(() => issueToken({ subject: "agent-42", scope: [], ttlSeconds: 300 }, store)).toThrow(InvalidScopeError);
  });

  it("refuses to issue a token that would already be expired", () => {
    const { store } = setup();
    expect(() => issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 0 }, store)).toThrow(InvalidScopeError);
  });
});

describe("issueToken with a policy attached", () => {
  it("issues normally when the request stays within the policy's constraints", () => {
    const { store, auditLog } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send", "crm:read"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      policyStore,
      auditLog,
    );

    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, policyId: policy.id }, store, policyStore);
    expect(token.scope).toEqual(["email:send"]);
  });

  it("refuses to issue a token whose scope exceeds the policy's allowedScope", () => {
    const { store, auditLog } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy(
      { name: "Email only", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      policyStore,
      auditLog,
    );

    expect(() =>
      issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 300, policyId: policy.id }, store, policyStore),
    ).toThrow(PolicyViolationError);
  });

  it("refuses to issue a token whose TTL exceeds the policy's maxTtlSeconds", () => {
    const { store, auditLog } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy(
      { name: "Short-lived only", allowedScope: ["email:send"], maxTtlSeconds: 60 },
      "policy-manager-1",
      policyStore,
      auditLog,
    );

    expect(() =>
      issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600, policyId: policy.id }, store, policyStore),
    ).toThrow(PolicyViolationError);
  });

  it("refuses to issue against an unknown policy id", () => {
    const { store } = setup();
    const policyStore = new PolicyStore();
    expect(() =>
      issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, policyId: "not-a-real-id" }, store, policyStore),
    ).toThrow(PolicyViolationError);
  });

  it("refuses to issue with a policyId when no PolicyStore is provided", () => {
    const { store } = setup();
    expect(() =>
      issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300, policyId: "some-id" }, store),
    ).toThrow(PolicyViolationError);
  });

  // "Given a policy, when it is modified, then changes are applied" — proven
  // here by actually re-issuing after modifying, not by inspecting the
  // stored policy record. The first issuance succeeds; after narrowing the
  // policy, the exact same request that worked before must now be denied.
  it("applies a policy modification to the very next issuance checked against it", () => {
    const { store, auditLog } = setup();
    const policyStore = new PolicyStore();
    const policy = createPolicy(
      { name: "Broad access", allowedScope: ["email:send", "payment:charge"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      policyStore,
      auditLog,
    );

    const first = issueToken({ subject: "agent-42", scope: ["payment:charge"], ttlSeconds: 300, policyId: policy.id }, store, policyStore);
    expect(first.scope).toEqual(["payment:charge"]);

    modifyPolicy(policy.id, { allowedScope: ["email:send"] }, "policy-manager-1", policyStore, auditLog);

    expect(() =>
      issueToken({ subject: "agent-99", scope: ["payment:charge"], ttlSeconds: 300, policyId: policy.id }, store, policyStore),
    ).toThrow(PolicyViolationError);
  });
});

describe("enforceToken", () => {
  it("allows an action within scope on an active, unexpired token", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    const decision = enforceToken(token.id, "email:send", store, auditLog);
    expect(decision).toEqual({ allowed: true });
  });

  it("logs every enforcement decision to the audit log", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    enforceToken(token.id, "email:send", store, auditLog);

    const entries = auditLog.entries();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      tokenId: token.id,
      subject: "agent-42",
      action: "email:send",
      decision: "allowed",
    });
    expect(entries[0]?.occurredAt).toBeInstanceOf(Date);
  });

  it("denies and logs an action outside the token's scope", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    const decision = enforceToken(token.id, "payment:charge", store, auditLog);

    expect(decision).toEqual({
      allowed: false,
      reasonCode: "out_of_scope",
      message: expect.stringContaining('does not include "payment:charge"'),
    });
    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        tokenId: token.id,
        action: "payment:charge",
        decision: "denied",
        reasonCode: "out_of_scope",
        message: expect.stringContaining('does not include "payment:charge"'),
      }),
    ]);
  });

  it("denies an action once the token has expired", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    const afterExpiry = new Date(token.expiresAt.getTime() + 1);

    const decision = enforceToken(token.id, "email:send", store, auditLog, afterExpiry);

    expect(decision).toEqual({
      allowed: false,
      reasonCode: "expired",
      message: expect.stringContaining(token.expiresAt.toISOString()),
    });
  });

  // Acceptance: "Given a rejected token, when it is used, then a detailed
  // error message is returned." — a bare reasonCode isn't enough; the
  // message must cite real, specific facts about the token itself.
  it("gives a detailed, specific message for each denial reason — not just a bare code", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send", "sms:send"], ttlSeconds: 300 }, store);

    const decision = enforceToken(token.id, "payment:charge", store, auditLog);

    if (decision.allowed) throw new Error("expected a denial");
    expect(decision.message).toContain(token.id);
    expect(decision.message).toContain("agent-42");
    expect(decision.message).toContain("email:send");
    expect(decision.message).toContain("sms:send");
    expect(decision.message.length).toBeGreaterThan(40); // genuinely detailed, not a restated code
  });

  // Acceptance: "Given a valid token, when it is used, then no error
  // message is returned." — checked as a real absence, not an empty string.
  it("returns no message field at all for an allowed decision", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    const decision = enforceToken(token.id, "email:send", store, auditLog);

    expect(decision).toEqual({ allowed: true });
    expect("message" in decision).toBe(false);
    expect(auditLog.entries()[0]?.message).toBeUndefined();
  });

  // Failure path: "Revocation status check fails" (STORY-002) generalizes to
  // "the token can't be confirmed at all" — an id nothing issued.
  it("denies and logs an action against an unknown token id", () => {
    const { store, auditLog } = setup();

    const decision = enforceToken("not-a-real-id", "email:send", store, auditLog);

    expect(decision).toEqual({
      allowed: false,
      reasonCode: "unknown_token",
      message: expect.stringContaining("not-a-real-id"),
    });
    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        tokenId: "not-a-real-id",
        decision: "denied",
        reasonCode: "unknown_token",
        message: expect.stringContaining("not-a-real-id"),
      }),
    ]);
  });
});
