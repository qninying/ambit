import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";

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
});
