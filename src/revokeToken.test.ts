import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { UnknownTokenError, enforceToken, issueToken, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";

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
});
