import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { UnknownTokenError, enforceToken, issueToken, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { delegateToken } from "./delegation.js";

function setup() {
  return { store: new TokenStore(), auditLog: new AuditLog() };
}

describe("revokeToken", () => {
  // Acceptance: "Given a token, when it is revoked, then its next call fails
  // immediately." — the proof is looking the token up BY ID again, not
  // reusing the object returned by issueToken, which is what makes this a
  // real test of the store rather than of a value the test already had.
  it("makes the very next enforceToken call by id fail, right after revocation", async () => {
    const { store, auditLog } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    revokeToken(token.id, store, auditLog, "compromised");
    const decision = await enforceToken(token.id, secret, "email:send", store, auditLog);

    expect(decision).toEqual({
      allowed: false,
      reasonCode: "revoked",
      message: expect.stringContaining("compromised"),
    });
  });

  // Acceptance: "Given a rejected token, when it is used, then a detailed
  // error message is returned." — for revocation specifically, "detailed"
  // means citing when it was revoked and why, not just "revoked" again.
  it("cites the real revocation time and reason in the denial message", async () => {
    const { store, auditLog } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    const revokedAt = new Date("2026-01-01T00:00:00.000Z");

    revokeToken(token.id, store, auditLog, "policy_violation", revokedAt);
    const decision = await enforceToken(token.id, secret, "email:send", store, auditLog);

    if (decision.allowed) throw new Error("expected a denial");
    expect(decision.message).toContain(revokedAt.toISOString());
    expect(decision.message).toContain("policy_violation");
  });

  // Acceptance: "Given a revoked token, when it is used, then the action is
  // blocked." Same mechanism as above; kept as its own test since it's a
  // named acceptance line, not just a restatement.
  it("blocks the action, not just reports a decision", async () => {
    const { store, auditLog } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["payment:charge"], ttlSeconds: 300 }, store);

    revokeToken(token.id, store, auditLog, "policy_violation");

    expect((await enforceToken(token.id, secret, "payment:charge", store, auditLog)).allowed).toBe(false);
  });

  // Acceptance: "Trust: Revocation is logged with a reason code."
  it("logs the revocation itself with the given reason code", async () => {
    const { store, auditLog } = setup();
    const { token } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    revokeToken(token.id, store, auditLog, "superseded");

    const entries = auditLog.entries();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      tokenId: token.id,
      subject: "agent-42",
      decision: "revoked",
      reasonCode: "superseded",
    });
  });

  it("updates the token's own status to revoked in the store", async () => {
    const { store, auditLog } = setup();
    const { token } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    revokeToken(token.id, store, auditLog, "no_longer_needed");

    expect(store.get(token.id)?.status).toBe("revoked");
  });

  // Failure path: "Revocation status check fails" — generalized here to
  // revoking something that was never issued, since there's no external
  // status check yet to fail against (that's what the Policy & Token Store
  // circuit-breaker guardrail is for, in a later story).
  it("refuses to revoke a token id that was never issued", () => {
    const { store, auditLog } = setup();
    expect(() => revokeToken("not-a-real-id", store, auditLog, "compromised")).toThrow(UnknownTokenError);
  });

  // ADR-015 (Control hardening): revocation is now gated by a real operator
  // session at the HTTP boundary — this proves the primitive actually
  // records who did it, not just that the route requires someone logged in.
  describe("actor attribution (ADR-015)", () => {
    it("records the given actor on the revocation's own audit entry", async () => {
      const { store, auditLog } = setup();
      const { token } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

      revokeToken(token.id, store, auditLog, "compromised", undefined, "operator-1");

      expect(auditLog.entries()).toContainEqual(
        expect.objectContaining({ tokenId: token.id, decision: "revoked", actor: "operator-1" }),
      );
    });

    it("attributes cascaded child revocations to the same actor who revoked the parent", async () => {
      const { store, auditLog } = setup();
      const { token: parent, secret: parentSecret } = await issueToken({ subject: "agent-42", scope: ["email:send", "crm:read"], ttlSeconds: 300 }, store);
      const childDecision = await delegateToken(parent.id, parentSecret, "subagent", ["email:send"], 60, store, auditLog);
      if (!childDecision.approved) throw new Error("unreachable");

      revokeToken(parent.id, store, auditLog, "compromised", undefined, "operator-1");

      const childEntry = auditLog.entries().find((e) => e.tokenId === childDecision.token.id && e.decision === "revoked");
      expect(childEntry).toMatchObject({ actor: "operator-1", reasonCode: "parent_revoked" });
    });

    it("leaves actor undefined when the caller doesn't supply one, matching every existing direct call site", async () => {
      const { store, auditLog } = setup();
      const { token } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

      revokeToken(token.id, store, auditLog, "compromised");

      expect(auditLog.entries()[0]?.actor).toBeUndefined();
    });
  });
});
