// REQ-005: log every allowed and blocked action to an immutable audit log.

export interface AuditLogEntry {
  id: string;
  occurredAt: Date;
  tokenId: string;
  subject: string;
  action: string;
  decision: "allowed" | "denied";
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
