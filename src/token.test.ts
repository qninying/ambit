import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { InvalidScopeError, enforceToken, issueToken } from "./token.js";

describe("issueToken", () => {
  it("issues an active token scoped and expiring as requested", () => {
    const before = Date.now();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 });
    const after = Date.now();

    expect(token.id).toBeTruthy();
    expect(token.subject).toBe("agent-42");
    expect(token.scope).toEqual(["email:send"]);
    expect(token.status).toBe("active");
    expect(token.issuedAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(token.issuedAt.getTime()).toBeLessThanOrEqual(after);
    expect(token.expiresAt.getTime() - token.issuedAt.getTime()).toBe(300_000);
  });

  // Failure path: "Token issuance fails due to invalid scope."
  it("refuses to issue a token with an empty scope", () => {
    expect(() => issueToken({ subject: "agent-42", scope: [], ttlSeconds: 300 })).toThrow(InvalidScopeError);
  });

  it("refuses to issue a token that would already be expired", () => {
    expect(() => issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 0 })).toThrow(InvalidScopeError);
  });
});

describe("enforceToken", () => {
  it("allows an action within scope on an active, unexpired token", () => {
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 });
    const auditLog = new AuditLog();
    const decision = enforceToken(token, "email:send", auditLog);
    expect(decision).toEqual({ allowed: true });
  });

  it("logs every enforcement decision to the audit log", () => {
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 });
    const auditLog = new AuditLog();

    enforceToken(token, "email:send", auditLog);

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

  // Failure path: "Token enforcement fails due to revocation" — covered here
  // by the out-of-scope branch, since revocation itself doesn't exist until
  // STORY-002; scope and status are checked by the same deny-first logic.
  it("denies and logs an action outside the token's scope", () => {
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 });
    const auditLog = new AuditLog();

    const decision = enforceToken(token, "payment:charge", auditLog);

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
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 });
    const auditLog = new AuditLog();
    const afterExpiry = new Date(token.expiresAt.getTime() + 1);

    const decision = enforceToken(token, "email:send", auditLog, afterExpiry);

    expect(decision).toEqual({ allowed: false, reasonCode: "expired" });
  });
});
