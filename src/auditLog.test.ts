import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLog, MissingReasonCodeError, computeEntryHash, verifyAuditChain } from "./auditLog.js";

// ADR-014: the audit log is the most safety-critical of the six stores this
// ADR touches — the real proof isn't just "entries survive a restart," it's
// that the hash chain a compliance reviewer would check still verifies
// clean, and that a NEW entry recorded after the restart correctly links to
// the last entry that existed before it rather than starting a fresh chain.
describe("AuditLog persistence (ADR-014)", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ambit-auditlog-test-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("entries recorded before a restart are still there, in order, after one", () => {
    const file = join(dir, "audit-log.jsonl");
    const before = new AuditLog(file);
    before.record({ subject: "agent-1", action: "email:send", decision: "allowed" });
    before.record({ subject: "agent-2", action: "crm:read", decision: "allowed" });

    const after = new AuditLog(file);
    const entries = after.entries();
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.subject)).toEqual(["agent-1", "agent-2"]);
    expect(entries[0]?.occurredAt).toBeInstanceOf(Date);
  });

  it("the hash chain still verifies clean after rehydration", () => {
    const file = join(dir, "audit-log.jsonl");
    const before = new AuditLog(file);
    before.record({ subject: "agent-1", action: "email:send", decision: "allowed" });
    before.record({ subject: "agent-1", action: "payment:charge", decision: "denied", reasonCode: "out_of_scope" });

    const after = new AuditLog(file);
    expect(after.verify()).toEqual({ valid: true, brokenAtId: null, entriesChecked: 2 });
  });

  // The real point of persisting an append-only log at all: a new entry
  // recorded after a restart must link to the real last entry from before
  // it, not start a fresh chain that would make the pre-restart history
  // unverifiable against what comes after.
  it("a new entry recorded after a restart correctly links to the last pre-restart entry", () => {
    const file = join(dir, "audit-log.jsonl");
    const before = new AuditLog(file);
    const first = before.record({ subject: "agent-1", action: "email:send", decision: "allowed" });

    const after = new AuditLog(file);
    const second = after.record({ subject: "agent-1", action: "crm:read", decision: "allowed" });

    expect(second.previousHash).toBe(first.hash);
    expect(after.verify()).toEqual({ valid: true, brokenAtId: null, entriesChecked: 2 });
  });
});

describe("AuditLog", () => {
  // REQ-010, structural guarantee: not just "every call site today happens
  // to supply a reasonCode" — the log itself refuses to accept one that
  // doesn't, so a future denial path can't silently reintroduce the gap
  // denyRequest's originally-optional parameter had.
  describe("REQ-010: reasonCode is required on every denial", () => {
    it("refuses a 'denied' entry with no reasonCode at all", () => {
      const auditLog = new AuditLog();
      expect(() => auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "denied" })).toThrow(
        MissingReasonCodeError,
      );
    });

    it("refuses a 'denied' entry with an empty-string reasonCode", () => {
      const auditLog = new AuditLog();
      expect(() =>
        auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "denied", reasonCode: "   " }),
      ).toThrow(MissingReasonCodeError);
    });

    it("refuses a 'request_denied' entry with no reasonCode", () => {
      const auditLog = new AuditLog();
      expect(() => auditLog.record({ requestId: "r1", subject: "agent-42", action: "deny_request", decision: "request_denied" })).toThrow(
        MissingReasonCodeError,
      );
    });

    it("accepts a 'denied' entry that does carry a reasonCode", () => {
      const auditLog = new AuditLog();
      const entry = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "denied", reasonCode: "expired" });
      expect(entry.reasonCode).toBe("expired");
    });

    // Non-denial decisions never needed a reasonCode and still don't — this
    // guarantee is scoped to denials specifically, not every entry.
    it("does not require a reasonCode on an 'allowed' decision", () => {
      const auditLog = new AuditLog();
      expect(() => auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" })).not.toThrow();
    });

    // Rejecting an invalid entry must not silently corrupt the chain —
    // nothing should be pushed, and the next valid entry still links back
    // to whatever the real last entry was before the rejected attempt.
    it("does not add a broken entry to the chain when rejecting a denial with no reasonCode", () => {
      const auditLog = new AuditLog();
      const first = auditLog.record({ tokenId: "t1", subject: "agent-42", action: "email:send", decision: "allowed" });

      expect(() => auditLog.record({ tokenId: "t2", subject: "agent-43", action: "email:send", decision: "denied" })).toThrow();

      const second = auditLog.record({ tokenId: "t3", subject: "agent-44", action: "email:send", decision: "allowed" });
      expect(auditLog.entries()).toHaveLength(2);
      expect(second.previousHash).toBe(first.hash);
    });
  });
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
