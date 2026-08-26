import { describe, expect, it } from "vitest";
import { AuditLog, computeEntryHash, verifyAuditChain } from "./auditLog.js";

describe("AuditLog", () => {
  it("returns a fresh array from entries() each call, not a live reference the caller could mutate", () => {
    const auditLog = new AuditLog();
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });

    const first = auditLog.entries();
    const second = auditLog.entries();

    expect(first).not.toBe(second);
    expect(first).toEqual(second);
  });

  it("assigns each entry a unique id and the given occurredAt", () => {
    const auditLog = new AuditLog();
    const now = new Date("2026-01-01T00:00:00Z");

    const a = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" }, now);
    const b = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" }, now);

    expect(a.id).not.toBe(b.id);
    expect(a.occurredAt).toEqual(now);
  });

  it("chains each entry to the previous one's hash, with a null previousHash for the first entry", () => {
    const auditLog = new AuditLog();
    const a = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });
    const b = auditLog.record({ tokenId: "t2", subject: "agent-43", action: "crm:read", decision: "allowed" });

    expect(a.previousHash).toBeNull();
    expect(b.previousHash).toBe(a.hash);
    expect(a.hash).not.toBe(b.hash);
  });

  it("verify() reports a real, untampered log as valid", () => {
    const auditLog = new AuditLog();
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "payment:charge", decision: "denied", reasonCode: "out_of_scope" });
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "revoke", decision: "revoked", reasonCode: "compromised" });

    expect(auditLog.verify()).toEqual({ valid: true, brokenAtId: null, entriesChecked: 3 });
  });

  it("verify() detects an empty log as trivially valid", () => {
    expect(new AuditLog().verify()).toEqual({ valid: true, brokenAtId: null, entriesChecked: 0 });
  });
});

describe("verifyAuditChain", () => {
  // The real proof this is tamper-EVIDENT, not just labelled immutable:
  // mutate one field on one entry in a plain array (entries() already
  // returns a copy, so this can't reach the log's real internal state) and
  // confirm the chain reports exactly where it breaks.
  it("detects a field changed on an entry after the fact", () => {
    const auditLog = new AuditLog();
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });
    const second = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "payment:charge", decision: "denied", reasonCode: "out_of_scope" });
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "revoke", decision: "revoked", reasonCode: "compromised" });

    const tampered = auditLog.entries().map((e) => (e.id === second.id ? { ...e, decision: "allowed" as const } : e));

    const result = verifyAuditChain(tampered);
    expect(result.valid).toBe(false);
    expect(result.brokenAtId).toBe(second.id);
  });

  it("detects a reordered/spliced entry via the previousHash link, not just the content hash", () => {
    const auditLog = new AuditLog();
    const a = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });
    auditLog.record({ tokenId: "t1", subject: "agent-42", action: "crm:read", decision: "allowed" });
    const c = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "revoke", decision: "revoked" });

    // Each entry's own hash is still internally self-consistent — only the
    // link between them is broken by removing the middle one.
    const withDeletedEntry = [a, c];

    const result = verifyAuditChain(withDeletedEntry);
    expect(result.valid).toBe(false);
    expect(result.brokenAtId).toBe(c.id);
  });

  it("an empty array is trivially valid", () => {
    expect(verifyAuditChain([])).toEqual({ valid: true, brokenAtId: null, entriesChecked: 0 });
  });

  it("computeEntryHash is deterministic for the same content", () => {
    const entry = {
      id: "x", occurredAt: new Date("2026-01-01T00:00:00Z"), subject: "agent-42",
      action: "email:send", decision: "allowed" as const, previousHash: null,
    };
    expect(computeEntryHash(entry)).toBe(computeEntryHash({ ...entry }));
  });
});
