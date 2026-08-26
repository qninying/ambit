import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { delegateToken } from "./delegation.js";
import { enforceToken, issueToken, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";

function setup() {
  return { store: new TokenStore(), auditLog: new AuditLog() };
}

describe("delegateToken", () => {
  // Acceptance: "Given a subagent request, when it is processed, then it
  // inherits a subset of the parent's scope."
  it("issues a child token with a strict subset of the parent's scope", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    const decision = delegateToken(parent.id, "subagent-1", ["email:send"], 300, store, auditLog);

    expect(decision.approved).toBe(true);
    if (!decision.approved) throw new Error("unreachable");
    expect(decision.token.scope).toEqual(["email:send"]);
    expect(decision.token.parentTokenId).toBe(parent.id);
    expect(store.get(decision.token.id)).toEqual(decision.token);
  });

  // Acceptance: "Given a subagent request, when it exceeds the parent's
  // scope, then it is denied."
  it("denies a request for scope the parent doesn't have", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

    const decision = delegateToken(parent.id, "subagent-1", ["payment:charge"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "exceeds_parent_scope" });
  });

  // REQ-003 says "strict subset" — the exact same scope back is not narrowing.
  it("denies a request for the parent's exact scope, since that isn't narrower", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    const decision = delegateToken(parent.id, "subagent-1", ["email:send", "payment:charge"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "not_narrower" });
  });

  it("denies an empty requested scope", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

    const decision = delegateToken(parent.id, "subagent-1", [], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "empty_scope" });
  });

  it("denies delegation from an unknown parent token", () => {
    const { store, auditLog } = setup();
    const decision = delegateToken("not-a-real-id", "subagent-1", ["email:send"], 300, store, auditLog);
    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  it("denies delegation from a revoked parent token", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    revokeToken(parent.id, store, auditLog, "compromised");

    const decision = delegateToken(parent.id, "subagent-1", ["email:send"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  it("denies delegation from an expired parent token", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 300 }, store);
    const afterExpiry = new Date(parent.expiresAt.getTime() + 1);

    const decision = delegateToken(parent.id, "subagent-1", ["email:send"], 300, store, auditLog, afterExpiry);

    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  // Acceptance: "Trust: Delegation actions are logged." — both outcomes.
  it("logs both an approved and a denied delegation attempt", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    delegateToken(parent.id, "subagent-1", ["email:send"], 300, store, auditLog);
    delegateToken(parent.id, "subagent-2", ["payment:charge", "sms:send"], 300, store, auditLog);

    const entries = auditLog.entries().filter((e) => e.action === "delegate");
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ decision: "allowed" });
    expect(entries[1]).toMatchObject({ decision: "denied", reasonCode: "exceeds_parent_scope" });
  });

  // A delegated token can never outlive the parent it was derived from, even
  // if a longer TTL was requested.
  it("caps a child token's expiry to the parent's, even if a longer TTL was requested", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 60 }, store);

    const decision = delegateToken(parent.id, "subagent-1", ["email:send"], 3600, store, auditLog);

    expect(decision.approved).toBe(true);
    if (!decision.approved) throw new Error("unreachable");
    expect(decision.token.expiresAt).toEqual(parent.expiresAt);
  });

  it("supports multi-level delegation — a subagent delegating to a sub-subagent", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send"], ttlSeconds: 3600 }, store);
    const childDecision = delegateToken(parent.id, "subagent-1", ["email:send", "payment:charge"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    const grandchildDecision = delegateToken(childDecision.token.id, "sub-subagent-1", ["email:send"], 300, store, auditLog);

    expect(grandchildDecision.approved).toBe(true);
    if (!grandchildDecision.approved) throw new Error("unreachable");
    expect(grandchildDecision.token.parentTokenId).toBe(childDecision.token.id);
  });
});

describe("revokeToken cascading", () => {
  it("revokes a delegated child when its parent is revoked", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    const childDecision = delegateToken(parent.id, "subagent-1", ["email:send"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    expect(store.get(childDecision.token.id)?.status).toBe("revoked");
    const decision = enforceToken(childDecision.token.id, "email:send", store, auditLog);
    expect(decision).toEqual({
      allowed: false,
      reasonCode: "revoked",
      message: expect.stringContaining("parent_revoked"),
    });
  });

  it("cascades through multiple generations — a sub-subagent's token is revoked too", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send"], ttlSeconds: 3600 }, store);
    const childDecision = delegateToken(parent.id, "subagent-1", ["email:send", "payment:charge"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");
    const grandchildDecision = delegateToken(childDecision.token.id, "sub-subagent-1", ["email:send"], 3600, store, auditLog);
    if (!grandchildDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    expect(store.get(childDecision.token.id)?.status).toBe("revoked");
    expect(store.get(grandchildDecision.token.id)?.status).toBe("revoked");
  });

  it("logs each cascaded revocation with its own entry and a distinct reason code", () => {
    const { store, auditLog } = setup();
    const parent = issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    const childDecision = delegateToken(parent.id, "subagent-1", ["email:send"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    const cascadeEntry = auditLog.entries().find((e) => e.tokenId === childDecision.token.id && e.decision === "revoked");
    expect(cascadeEntry).toMatchObject({ reasonCode: "parent_revoked" });
  });
});
