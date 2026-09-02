# ADR-020: Structured Operational Logging

**Status:** Implemented. Closes the INPACT trust scorecard's Transparency dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/logger.ts`, `src/jsonlStore.ts`, `src/server.ts`

---

## Context

The hash-chained audit log (ADR-008) captures every *domain* event — approvals, denials, revocations, policy changes. The 2026-09-01 INPACT assessment named what it doesn't cover: *operational* events outside that trail. Grepping the codebase turned up exactly three real, unstructured `console.*` calls — a corrupted line skipped during JSONL rehydration (a bare string), a startup message (a bare string), and, most importantly, the catch-all error middleware's `console.error(err)` for any genuinely unexpected exception — no timestamp, no event name, no error classification, nothing to grep, filter, or alert on.

## Decision

**Ported CoreOps's own `observability/logger.ts` directly, scaled to what Ambit actually has.** One `logEvent({ level, event, context })` function in `src/logger.ts`, one JSON object per line (`timestamp`, `level`, `service: "ambit"`, `event`, `context`).

**One deliberate simplification from CoreOps's version:** CoreOps writes to `stderr` (via `console.error`) specifically because its MCP stdio transport reserves stdout exclusively for the JSON-RPC protocol stream — writing anything else to stdout there would corrupt it. Ambit has no MCP server (a deliberate scope decision, recorded separately, not an oversight here) and no such constraint, so `logEvent()` writes to plain stdout via `console.log`, matching the Observability Framework's general "logs go to stdout" default directly rather than inheriting a workaround for a problem Ambit doesn't have.

**Also deliberately not ported:** CoreOps's `safeLogEvent()` try/catch wrapper, added there after three real call sites needed it. Ambit's `logEvent()` is a single `JSON.stringify` + `console.log` over simple, already-serializable objects — a materially lower-risk operation than CoreOps's own multi-service call sites — so the wrapper would be defending against a failure mode with no track record here. Revisit if that changes.

**All three existing call sites now use it:**
- `src/jsonlStore.ts`'s corrupted-line skip during rehydration → `logEvent({ level: "warn", event: "jsonl_line_skipped", context: { filePath, lineNumber, error } })`.
- `src/server.ts`'s catch-all error middleware → `logEvent({ level: "error", event: "unhandled_error", context: { errorClass, message } })`. The single most valuable of the three: this is the one path that catches genuinely unexpected bugs, and it now names a real error class (`err.constructor.name`) rather than dumping an unstructured object.
- `src/server.ts`'s startup message → `logEvent({ level: "info", event: "server_started", context: { port } })`.

**Deliberately out of scope, named rather than silently expanded into:** correlation-ID propagation across requests and downstream calls. The root CLAUDE.md's Observability Framework describes that for the larger Colaberry platform stack; the INPACT finding for Ambit specifically named "no structured logging layer," not "no correlation IDs." Adding request-tracing now would be real, separate scope beyond what this gap actually asked for.

## Consequences

**What this closes:** Transparency's one remaining named gap. **Transparency moves from Band 3 to Band 4 (Hardened).** New aggregate: Identity 4 + Non-repudiation 4 + Provenance 3 + Accountability 4 + Control 4 + Transparency 4 = 23/6 = **3.83/4**, up from 3.67/4. Only Provenance remains before 4/4.

**What this does not cover:**
- No correlation IDs / distributed tracing (named above).
- No log shipping or external aggregation — this is a local stdout stream, the same "no distributed infrastructure exists for this system" limitation ADR-006/014/018 already named for every other store.
- No `safeLogEvent()`-style defensive wrapper (named above) — revisit if `logEvent()` itself is ever seen to throw in practice.

## Verification

9 new/updated tests. `logger.test.ts` (5, new — logs to `console.log` not `console.error`, produces valid JSON with all required fields, defaults `context` to `{}`, supports all three levels). `jsonlStore.test.ts`'s two existing skip tests updated (they previously spied on the old bare `console.error` call; now assert the real structured `jsonl_line_skipped` shape, including the exact `filePath`/`lineNumber`). `server.test.ts` gained a new real-HTTP test proving the error middleware's wiring specifically: malformed JSON in a request body is a genuine, natural trigger — `express.json()` throws a real `SyntaxError` that Express routes straight to this middleware, not a contrived path — confirmed a real `500` response and a real `unhandled_error` log line with `errorClass: "SyntaxError"`. 324/324 total passing, `tsc --noEmit` clean.

Live-verified against a real running server for all three call sites, not just tests: real stdout output for `server_started` on boot; sent genuinely malformed JSON over `curl` and confirmed the real `unhandled_error` line, `errorClass: "SyntaxError"`, with the real parser's own message; seeded a real corrupted line into a real persisted `agent-identities.jsonl` file and confirmed the real `jsonl_line_skipped` line on startup, with the correct file path and line number.

## What would change this decision

A real need for cross-service request tracing (multiple Ambit processes, or a downstream system whose logs need correlating with Ambit's) would be the trigger to add correlation IDs — the same threshold that kept it out of scope here. A real failure observed inside `logEvent()` itself would be the trigger to add CoreOps's `safeLogEvent()` wrapper.
