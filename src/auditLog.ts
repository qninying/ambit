// REQ-005: log every allowed and blocked action to an immutable audit log.
// "revoked" isn't an enforcement decision but shares the same trail — REQ-010
// (reason-coded denials) and STORY-002's "revocation logged with a reason
// code" are both instances of the same underlying need: one durable record
// of what happened to a token and why, not two separate logs to cross-check.
//
// "Immutable" was previously just a comment on entries() returning a copy —
// nothing detected if the underlying data had actually been altered. Each
// entry's hash now covers its own content plus the previous entry's hash
// (same principle as a certificate transparency log), so altering any entry
// breaks the hash of every entry after it. Node's built-in `crypto`, no new
// dependency.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, renameSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

export interface AuditLogEntry {
  id: string;
  occurredAt: Date;
  // tokenId is only present once a real token exists — a denied request
  // never gets one, per "Denied request is incorrectly issued" being a
  // failure path STORY-003 has to actually prevent, not just log around.
  tokenId?: string;
  requestId?: string;
  policyId?: string;
  subject: string;
  action: string;
  decision:
    | "allowed"
    | "denied"
    | "revoked"
    | "request_submitted"
    | "request_approved"
    | "request_denied"
    | "anomaly_detected"
    | "policy_created"
    | "policy_modified"
    | "circuit_opened"
    | "circuit_closed"
    | "redaction_rule_created"
    | "data_accessed"
    | "agent_identity_registered"
    | "token_secret_claimed";
  reasonCode?: string;
  // REQ-018: the detailed, human-readable explanation behind a denial —
  // present only on denials, matching "no error message is returned" for
  // an allowed decision. reasonCode stays for programmatic branching;
  // this is for the developer/administrator reading the trail.
  message?: string;
  // Who performed a human-driven action (an approver), as opposed to
  // `subject`, which is the AI agent the token is for.
  actor?: string;
  // What actually happened downstream, for a mock-endpoint access — distinct
  // from `decision`, which only says whether the Enforcement Gateway allowed
  // the attempt. A gateway can allow an action that then fails to reach its
  // target; those are two different facts, logged as two entries.
  outcome?: "success" | "unreachable";
  // REQ-009: which fields a redaction pass actually masked on this access —
  // a separate fact from the access decision itself, same "decision vs
  // outcome, two entries" principle as `outcome` above (ADR-005).
  redactedFields?: string[];
  // Chain fields — null previousHash marks the genesis entry. hash covers
  // every other field on this entry (including previousHash), computed by
  // computeEntryHash() below.
  previousHash: string | null;
  hash: string;
}

export function computeEntryHash(entry: Omit<AuditLogEntry, "hash">): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

export interface ChainVerification {
  valid: boolean;
  brokenAtId: string | null;
  entriesChecked: number;
}

// A pure function over any entry array — not a method reading private
// state — so it can verify the real log's entries() output, or a
// deliberately-tampered array in a test, and report exactly which entry the
// chain breaks at rather than just "somewhere."
export function verifyAuditChain(entries: readonly AuditLogEntry[]): ChainVerification {
  let expectedPrevious: string | null = null;
  for (const entry of entries) {
    const { hash, ...rest } = entry;
    if (rest.previousHash !== expectedPrevious || computeEntryHash(rest) !== hash) {
      return { valid: false, brokenAtId: entry.id, entriesChecked: entries.length };
    }
    expectedPrevious = hash;
  }
  return { valid: true, brokenAtId: null, entriesChecked: entries.length };
}

// REQ-010: which decisions represent an attempted action being refused —
// "circuit_opened" or "revoked" are real events but not themselves a
// denial of an attempted action (the store_unavailable/revoked denials
// those cause are separately logged as "denied" already), so they're
// deliberately excluded from this set.
const DENIAL_DECISIONS: ReadonlySet<AuditLogEntry["decision"]> = new Set(["denied", "request_denied"]);

export class MissingReasonCodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MissingReasonCodeError";
  }
}

function reviveAuditLogEntry(raw: unknown): AuditLogEntry {
  const e = raw as AuditLogEntry & { occurredAt: string };
  return { ...e, occurredAt: new Date(e.occurredAt) };
}

export interface AuditLogOptions {
  // ADR-018: once the active persisted file reaches this many lines, it's
  // rotated into a numbered archive segment (e.g. audit-log.1.jsonl) and a
  // fresh active file starts — bounding any single file's size without ever
  // deleting history, since this is a governance record, not a disposable
  // debug log. Only meaningful when persistTo is set. Same default CoreOps's
  // own ADR-005 addendum chose, for the same reason: comfortably above this
  // system's actual volume, small enough that any archived file stays easy
  // to open and read directly.
  maxLinesPerSegment?: number;
}

const DEFAULT_MAX_LINES_PER_SEGMENT = 5_000;

// Archived segments sit next to the active file, named `<base>.<n><ext>`
// (audit-log.jsonl -> audit-log.1.jsonl, audit-log.2.jsonl, ...). No
// separate index file or persisted counter needed — the next index is
// always derivable by scanning the directory, cheap at this system's
// volume. Ported from CoreOps's own auditLog.ts (ADR-005 addendum).
function archiveSegmentPattern(activePath: string): RegExp {
  const ext = extname(activePath);
  const base = basename(activePath, ext);
  const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escape(base)}\\.(\\d+)${escape(ext)}$`);
}

function scanArchivedSegments(activePath: string): Array<{ path: string; index: number }> {
  const dir = dirname(activePath);
  if (!existsSync(dir)) return [];
  const pattern = archiveSegmentPattern(activePath);
  return readdirSync(dir)
    .map((name) => {
      const match = name.match(pattern);
      return match ? { path: join(dir, name), index: Number(match[1]) } : null;
    })
    .filter((entry): entry is { path: string; index: number } => entry !== null)
    .sort((a, b) => a.index - b.index);
}

function nextArchiveSegmentPath(activePath: string): string {
  const segments = scanArchivedSegments(activePath);
  const nextIndex = segments.length > 0 ? segments[segments.length - 1]!.index + 1 : 1;
  const ext = extname(activePath);
  const base = basename(activePath, ext);
  return join(dirname(activePath), `${base}.${nextIndex}${ext}`);
}

// Counts physical non-blank lines, not parsed entries — a corrupted tail
// line (see rehydrateJsonLines's own skip-and-warn handling) still takes up
// space in the file and must still count toward the rotation threshold,
// same reasoning CoreOps's own implementation states for itself.
function countPhysicalLines(filePath: string): number {
  if (!existsSync(filePath)) return 0;
  return readFileSync(filePath, "utf-8").split("\n").filter((line) => line.trim().length > 0).length;
}

export class AuditLog {
  #entries: AuditLogEntry[] = [];
  #persistTo?: string;
  #maxLinesPerSegment: number;
  #currentSegmentLines = 0;

  // ADR-014: the audit log is append-only by nature already (record() never
  // updates an existing entry), the same shape CoreOps's ADR-005 built this
  // exact pattern for — rehydration replays every persisted entry, in
  // order, into #entries BEFORE any new record() call, so a hash chain that
  // continues after a restart links correctly to the last entry that
  // existed before it, not a fresh genesis entry. Every entry already
  // carries its own hash/previousHash from when it was first recorded, so
  // rehydration trusts and loads them rather than recomputing — exactly
  // what verify() already does when checking any entry array.
  //
  // ADR-018: archived segments (oldest first, by index) are rehydrated
  // before the active file, so #entries preserves the same chronological
  // insertion order a restart always had — verify() itself needs no changes
  // at all, since it only ever walks this in-memory array and has no idea
  // how many physical files that array's history is actually split across.
  constructor(persistTo?: string, options: AuditLogOptions = {}) {
    this.#persistTo = persistTo;
    this.#maxLinesPerSegment = options.maxLinesPerSegment ?? DEFAULT_MAX_LINES_PER_SEGMENT;
    if (persistTo) {
      for (const segment of scanArchivedSegments(persistTo)) {
        this.#entries.push(...rehydrateJsonLines(segment.path, reviveAuditLogEntry));
      }
      this.#entries.push(...rehydrateJsonLines(persistTo, reviveAuditLogEntry));
      this.#currentSegmentLines = countPhysicalLines(persistTo);
    }
  }

  // Called immediately before an append, never after — so an archived
  // segment always ends up with exactly maxLinesPerSegment lines and the
  // active file never exceeds it. If the active file is already gone (a
  // rotation happened but the process crashed before the next append
  // landed), there's nothing to rename; just reset the counter.
  #rotateIfNeeded(): void {
    if (!this.#persistTo) return;
    if (this.#currentSegmentLines < this.#maxLinesPerSegment) return;
    if (!existsSync(this.#persistTo)) {
      this.#currentSegmentLines = 0;
      return;
    }
    renameSync(this.#persistTo, nextArchiveSegmentPath(this.#persistTo));
    this.#currentSegmentLines = 0;
  }

  record(entry: Omit<AuditLogEntry, "id" | "occurredAt" | "previousHash" | "hash">, now: Date = new Date()): AuditLogEntry {
    // REQ-010, structural guarantee: not just "every call site today
    // happens to supply one" — the log itself refuses to accept a denial
    // with no reason, so a future call site can't silently reintroduce
    // this gap the way denyRequest's optional parameter originally did.
    if (DENIAL_DECISIONS.has(entry.decision) && (!entry.reasonCode || entry.reasonCode.trim().length === 0)) {
      throw new MissingReasonCodeError(
        `a "${entry.decision}" audit entry must include a reasonCode — REQ-010 requires every denied action to record a distinct reason, not just be logged as denied`,
      );
    }
    const previousHash = this.#entries.length > 0 ? this.#entries[this.#entries.length - 1]!.hash : null;
    const withoutHash: Omit<AuditLogEntry, "hash"> = {
      id: crypto.randomUUID(),
      occurredAt: now,
      previousHash,
      ...entry,
    };
    const full: AuditLogEntry = { ...withoutHash, hash: computeEntryHash(withoutHash) };
    this.#entries.push(full);
    if (this.#persistTo) {
      this.#rotateIfNeeded();
      appendJsonLine(this.#persistTo, full);
      this.#currentSegmentLines += 1;
    }
    return full;
  }

  // Returns a copy, not the live array — callers can read the trail but can't
  // mutate or truncate it. The hash chain is what makes tampering with that
  // copy (or with a compromised process's memory) *detectable*, which is
  // what "immutable" actually has to mean for an audit log, not just that
  // this one method happens to return a new array.
  entries(): readonly AuditLogEntry[] {
    return [...this.#entries];
  }

  verify(): ChainVerification {
    return verifyAuditChain(this.#entries);
  }
}
