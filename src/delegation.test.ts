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
  it("issues a child token with a strict subset of the parent's scope", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 300, store, auditLog);

    expect(decision.approved).toBe(true);
    if (!decision.approved) throw new Error("unreachable");
    expect(decision.token.scope).toEqual(["email:send"]);
    expect(decision.token.parentTokenId).toBe(parent.id);
    expect(decision.secret).toBeTruthy();
    expect(store.get(decision.token.id)).toEqual(decision.token);
  });

  // Acceptance: "Given a subagent request, when it exceeds the parent's
  // scope, then it is denied."
  it("denies a request for scope the parent doesn't have", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["payment:charge"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "exceeds_parent_scope" });
  });

  // REQ-003 says "strict subset" — the exact same scope back is not narrowing.
  it("denies a request for the parent's exact scope, since that isn't narrower", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send", "payment:charge"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "not_narrower" });
  });

  it("denies an empty requested scope", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", [], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "empty_scope" });
  });

  it("denies delegation from an unknown parent token", async () => {
    const { store, auditLog } = setup();
    const decision = await delegateToken("not-a-real-id", "irrelevant-secret", "subagent-1", ["email:send"], 300, store, auditLog);
    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  it("denies delegation from a revoked parent token", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    revokeToken(parent.id, store, auditLog, "compromised");

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 300, store, auditLog);

    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  it("denies delegation from an expired parent token", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 300 }, store);
    const afterExpiry = new Date(parent.expiresAt.getTime() + 1);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 300, store, auditLog, afterExpiry);

    expect(decision).toEqual({ approved: false, reasonCode: "parent_invalid" });
  });

  // Acceptance: "Trust: Delegation actions are logged." — both outcomes.
  it("logs both an approved and a denied delegation attempt", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);

    await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 300, store, auditLog);
    await delegateToken(parent.id, parentSecret, "subagent-2", ["payment:charge", "sms:send"], 300, store, auditLog);

    const entries = auditLog.entries().filter((e) => e.action === "delegate");
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ decision: "allowed" });
    expect(entries[1]).toMatchObject({ decision: "denied", reasonCode: "exceeds_parent_scope" });
  });

  // A delegated token can never outlive the parent it was derived from, even
  // if a longer TTL was requested.
  it("caps a child token's expiry to the parent's, even if a longer TTL was requested", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 60 }, store);

    const decision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 3600, store, auditLog);

    expect(decision.approved).toBe(true);
    if (!decision.approved) throw new Error("unreachable");
    expect(decision.token.expiresAt).toEqual(parent.expiresAt);
  });

  it("supports multi-level delegation — a subagent delegating to a sub-subagent", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send"], ttlSeconds: 3600 }, store);
    const childDecision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send", "payment:charge"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    const grandchildDecision = await delegateToken(childDecision.token.id, childDecision.secret, "sub-subagent-1", ["email:send"], 300, store, auditLog);

    expect(grandchildDecision.approved).toBe(true);
    if (!grandchildDecision.approved) throw new Error("unreachable");
    expect(grandchildDecision.token.parentTokenId).toBe(childDecision.token.id);
  });

  // ADR-013: delegating spends some of the parent's authority — minting a
  // child from it requires the same proof of possession using it directly
  // would, not just knowledge of its (public) id.
  describe("possession proof", () => {
    it("denies delegation with invalid_credential when the wrong parent secret is provided", async () => {
      const { store, auditLog } = setup();
      const { token: parent } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

      const decision = await delegateToken(parent.id, "not-the-real-secret", "subagent-1", ["email:send"], 300, store, auditLog);

      expect(decision).toEqual({ approved: false, reasonCode: "invalid_credential" });
    });

    it("denies delegation with invalid_credential when no parent secret is provided at all", async () => {
      const { store, auditLog } = setup();
      const { token: parent } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 3600 }, store);

      const decision = await delegateToken(parent.id, "", "subagent-1", ["email:send"], 300, store, auditLog);

      expect(decision).toEqual({ approved: false, reasonCode: "invalid_credential" });
    });

    // The child's own secret — not the parent's — is what's needed to use
    // or further delegate the child. Proves the two aren't interchangeable.
    it("a child's secret does not work as a credential for its parent, or vice versa", async () => {
      const { store, auditLog } = setup();
      const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
      const childDecision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 300, store, auditLog);
      if (!childDecision.approved) throw new Error("unreachable");

      const usingChildSecretOnParent = await enforceToken(parent.id, childDecision.secret, "email:send", store, auditLog);
      const usingParentSecretOnChild = await enforceToken(childDecision.token.id, parentSecret, "email:send", store, auditLog);

      expect(usingChildSecretOnParent).toMatchObject({ allowed: false, reasonCode: "invalid_credential" });
      expect(usingParentSecretOnChild).toMatchObject({ allowed: false, reasonCode: "invalid_credential" });
    });
  });
});

describe("revokeToken cascading", () => {
  it("revokes a delegated child when its parent is revoked", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    const childDecision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    expect(store.get(childDecision.token.id)?.status).toBe("revoked");
    const decision = await enforceToken(childDecision.token.id, childDecision.secret, "email:send", store, auditLog);
    expect(decision).toEqual({
      allowed: false,
      reasonCode: "revoked",
      message: expect.stringContaining("parent_revoked"),
    });
  });

  it("cascades through multiple generations — a sub-subagent's token is revoked too", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge", "sms:send"], ttlSeconds: 3600 }, store);
    const childDecision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send", "payment:charge"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");
    const grandchildDecision = await delegateToken(childDecision.token.id, childDecision.secret, "sub-subagent-1", ["email:send"], 3600, store, auditLog);
    if (!grandchildDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    expect(store.get(childDecision.token.id)?.status).toBe("revoked");
    expect(store.get(grandchildDecision.token.id)?.status).toBe("revoked");
  });

  it("logs each cascaded revocation with its own entry and a distinct reason code", async () => {
    const { store, auditLog } = setup();
    const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "payment:charge"], ttlSeconds: 3600 }, store);
    const childDecision = await delegateToken(parent.id, parentSecret, "subagent-1", ["email:send"], 3600, store, auditLog);
    if (!childDecision.approved) throw new Error("unreachable");

    revokeToken(parent.id, store, auditLog, "compromised");

    const cascadeEntry = auditLog.entries().find((e) => e.tokenId === childDecision.token.id && e.decision === "revoked");
    expect(cascadeEntry).toMatchObject({ reasonCode: "parent_revoked" });
  });
});
