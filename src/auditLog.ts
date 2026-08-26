// REQ-005: log every allowed and blocked action to an immutable audit log.
// "revoked" isn't an enforcement decision but shares the same trail — REQ-010
// (reason-coded denials) and STORY-002's "revocation logged with a reason
// code" are both instances of the same underlying need: one durable record
// of what happened to a token and why, not two separate logs to cross-check.

export interface AuditLogEntry {
  id: string;
  occurredAt: Date;
  tokenId: string;
  subject: string;
  action: string;
  decision: "allowed" | "denied" | "revoked";
  reasonCode?: string;
}

export class AuditLog {
  #entries: AuditLogEntry[] = [];

  record(entry: Omit<AuditLogEntry, "id" | "occurredAt">, now: Date = new Date()): AuditLogEntry {
    const full: AuditLogEntry = { id: crypto.randomUUID(), occurredAt: now, ...entry };
    this.#entries.push(full);
    return full;
  }

  // Returns a copy, not the live array — callers can read the trail but can't
  // mutate or truncate it, which is what "immutable" means for an audit log.
  entries(): readonly AuditLogEntry[] {
    return [...this.#entries];
  }
}
