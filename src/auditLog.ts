// REQ-005: log every allowed and blocked action to an immutable audit log.
// "revoked" isn't an enforcement decision but shares the same trail — REQ-010
// (reason-coded denials) and STORY-002's "revocation logged with a reason
// code" are both instances of the same underlying need: one durable record
// of what happened to a token and why, not two separate logs to cross-check.

export interface AuditLogEntry {
  id: string;
  occurredAt: Date;
  // tokenId is only present once a real token exists — a denied request
  // never gets one, per "Denied request is incorrectly issued" being a
  // failure path STORY-003 has to actually prevent, not just log around.
  tokenId?: string;
  requestId?: string;
  subject: string;
  action: string;
  decision: "allowed" | "denied" | "revoked" | "request_approved" | "request_denied" | "anomaly_detected";
  reasonCode?: string;
  // Who performed a human-driven action (an approver), as opposed to
  // `subject`, which is the AI agent the token is for.
  actor?: string;
  // What actually happened downstream, for a mock-endpoint access — distinct
  // from `decision`, which only says whether the Enforcement Gateway allowed
  // the attempt. A gateway can allow an action that then fails to reach its
  // target; those are two different facts, logged as two entries.
  outcome?: "success" | "unreachable";
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
