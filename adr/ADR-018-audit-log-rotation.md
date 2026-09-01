# ADR-018: Audit Log Rotation — Closing the Non-repudiation Dimension

**Status:** Implemented. Closes the INPACT trust scorecard's Non-repudiation dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/auditLog.ts`, `src/server.ts`

---

## Context

ADR-014 made the hash-chained audit log (ADR-008) survive a real restart, persisting to one append-only JSONL file. The 2026-09-01 INPACT assessment named the gap that left open: nothing bounds that file's size — it grows forever. Exactly the gap CoreOps's own ADR-005 addendum named and closed for itself the same way.

## Decision

**Ported CoreOps's own rotation design directly**, not reinvented: size-based rotation into numbered archive segments, never deletion. This is a governance record, not a disposable debug log — every entry ever recorded has to stay queryable indefinitely, so "rotation" here only means bounding any *single* file's size, not expiring history.

- `AuditLog` gains an optional `maxLinesPerSegment` constructor option (default `5,000`, same default CoreOps chose, for the same reason — comfortably above this system's real volume, small enough that any one archived file stays easy to open and read directly).
- Once the active `persistTo` file reaches that many lines, the check runs immediately before the *next* append (never after), so an archived segment always ends up with exactly `maxLinesPerSegment` lines and the active file never exceeds it: the active file is renamed to a numbered archive segment (`audit-log.jsonl` → `audit-log.1.jsonl`, `.2.jsonl`, ...), and a fresh active file starts. No separate index file or persisted counter — the next index is derived by scanning the directory, cheap at this system's volume.
- Rehydration on startup now reads every archived segment (oldest first, by index) and then the active file, replaying all of them into the same in-memory array exactly as before.
- **The hash chain needed zero new logic.** `verify()`/`verifyAuditChain()` only ever walk the in-memory `entries()` array — they have no notion of files at all, so rotation is invisible to them by construction. The only real risk this ADR had to actually test for wasn't "does rotation happen," it was "does everything downstream (rehydration order, the chain link across the boundary, in-order history) stay correct once history is split across files" — which is exactly what the new tests check.
- Wired at the one call site in `server.ts`: `new AuditLog(dataFile("audit-log"), { maxLinesPerSegment: envNumber("AUDIT_LOG_MAX_LINES_PER_SEGMENT") })` — overridable, same "not hardcoded" treatment as every other judgment-call threshold in this codebase.

**Scope held to exactly what was named.** Rotation applies to the audit log only — not the other five JSONL-backed stores (tokens, requests, policies, redaction rules, agent identities). That's what both the trust-scorecard gap and CoreOps's own precedent actually named; those stores are "current state by id" (a later line supersedes an earlier one on rehydration), a different unbounded-growth shape that wasn't in scope here. The rotation logic itself lives directly in `auditLog.ts`, not extracted into the shared `jsonlStore.ts` module — one consumer today, not three, matching CoreOps's own choice to keep this in its `auditLog.ts` rather than a shared file.

**One difference from CoreOps, deliberate:** CoreOps's `record()` takes a caller-supplied `id`, so a retried write with the same id and identical content is a safe no-op (idempotent by design), and CoreOps names that as one of its rotation test cases ("idempotent duplicates near a rotation boundary don't rotate twice"). Ambit's `AuditLog.record()` always mints a fresh `crypto.randomUUID()` internally — there's no caller-supplied id, so that specific test case doesn't map onto this codebase at all. Flagged here rather than silently dropped: it wasn't skipped by oversight, it doesn't apply.

## Consequences

**What this closes:** Non-repudiation's one remaining named gap. **Non-repudiation moves from Band 3 to Band 4 (Hardened).** New aggregate: Identity 4 + Non-repudiation 4 + Provenance 3 + Accountability 3 + Control 4 + Transparency 3 = 21/6 = **3.5/4**, up from 3.33/4.

**What this does not cover:**
- No distributed storage — still a single process's local filesystem, the same limitation ADR-006/014 already named for every other store.
- No log shipping or offsite archival — rotated segments stay on the same disk as the active file, just as smaller files.
- Time-based rotation was considered and rejected, matching CoreOps's own reasoning: size-based directly bounds what actually matters (file size, rehydration cost), where a time-based scheme would let a burst of activity produce one huge daily file just the same.

## Verification

7 new tests in `auditLog.test.ts`'s new "AuditLog rotation (ADR-018)" block: doesn't rotate before the threshold, rotates into a numbered segment exactly at the threshold, rehydrates every entry in order across an archived segment and the active file, the hash chain verifies clean across the boundary, a new entry recorded after rehydrating across a rotation still links to the real last pre-restart entry, multiple sequential rotations produce multiple correctly-ordered segments, and the default threshold is high enough that ordinary use never rotates. 296/296 total passing, `tsc --noEmit` clean.

Live-verified against a real running server, not just tests: started with `AUDIT_LOG_MAX_LINES_PER_SEGMENT=3` and a real `AMBIT_DATA_DIR`, logged in for real, registered 6 agent identities over real HTTP (8 real entries total, including the startup redaction-rule bootstrap and the login itself). Confirmed on disk: `audit-log.1.jsonl` (3 lines), `audit-log.2.jsonl` (3 lines), `audit-log.jsonl` (2 lines) — two real rotations, exactly as designed. `GET /audit-log/verify` returned `{"valid":true,"brokenAtId":null,"entriesChecked":8}` over real HTTP. Confirmed in the actual Console UI's Audit Log tab: **"CHAIN VERIFIED — 8 ENTRIES"**, with all 8 entries rendering in the correct order across the file boundary.

## What would change this decision

Horizontal scaling or a compliance requirement for offsite/immutable archival (e.g. write-once storage, a separate log-shipping pipeline) would be the trigger to move past local-filesystem rotation — the same threshold ADR-006/014 already named for every other store in this system.
