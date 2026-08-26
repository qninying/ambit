import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { InvalidScopeError, enforceToken, issueToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";

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

    expect(decision).toEqual({ allowed: false, reasonCode: "out_of_scope" });
    expect(auditLog.entries()).toEqual([
      expect.objectContaining({
        tokenId: token.id,
        action: "payment:charge",
        decision: "denied",
        reasonCode: "out_of_scope",
      }),
    ]);
  });

  it("denies an action once the token has expired", () => {
    const { store, auditLog } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    const afterExpiry = new Date(token.expiresAt.getTime() + 1);

    const decision = enforceToken(token.id, "email:send", store, auditLog, afterExpiry);

    expect(decision).toEqual({ allowed: false, reasonCode: "expired" });
  });

  // Failure path: "Revocation status check fails" (STORY-002) generalizes to
  // "the token can't be confirmed at all" — an id nothing issued.
  it("denies and logs an action against an unknown token id", () => {
    const { store, auditLog } = setup();

    const decision = enforceToken("not-a-real-id", "email:send", store, auditLog);

    expect(decision).toEqual({ allowed: false, reasonCode: "unknown_token" });
    expect(auditLog.entries()).toEqual([
      expect.objectContaining({ tokenId: "not-a-real-id", decision: "denied", reasonCode: "unknown_token" }),
    ]);
  });
});
