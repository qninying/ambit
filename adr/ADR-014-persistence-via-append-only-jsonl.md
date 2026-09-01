# ADR-014: Persistence via Append-Only JSONL — Closing ADR-009's Fourth Item

**Status:** Implemented — all six stores, opt-in via `AMBIT_DATA_DIR`, live-verified across a real process restart.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/jsonlStore.ts`, `src/tokenStore.ts`, `src/requestStore.ts`, `src/policy.ts`, `src/agentIdentity.ts`, `src/redaction.ts`, `src/auditLog.ts`, `src/server.ts`

---

## Context

ADR-006 chose in-memory `Map`-backed stores deliberately, named the graduation path explicitly (append-only JSONL, zero new dependency, matching CoreOps's own ADR-005), and left it as ADR-009's fourth and final open item. With authentication and possession proof closed (ADR-011/012/013), this was the one substantial gap left: every restart erased every token, request, policy, agent identity, redaction rule, and audit entry.

## Decision drivers

Same three as ADR-006 anticipated, now acted on: zero new dependency (`node:fs` only, matching this repo's own "deliberate add" rule for anything heavier); the interface graduation ADR-006 promised (`get`/`save`/`list` unchanged everywhere — no caller of any store had to change); and not hiding the tradeoff (persistence is opt-in, off by default, every existing test's in-memory behavior is untouched).

## Decision

**One shared module, `src/jsonlStore.ts`**, not six reimplementations — `appendJsonLine`/`rehydrateJsonLines`, ported from CoreOps's ADR-005 pattern. A corrupted or unparseable line is skipped with a loud `console.error`, not a fatal startup error (same reasoning as CoreOps: the likely cause is a truncated final line from a crash mid-append).

**Every store gains an optional `persistTo` constructor parameter** (`TokenStore`/`PolicyStore`'s is the second argument, after their existing optional `breaker`; every other store's is the first and only new one). Rehydration replays every line in file order through the store's own `save()` semantics — for the five "current state by id" stores (`TokenStore`, `RequestStore`, `PolicyStore`, `AgentIdentityStore`, `RedactionRuleStore`), a later line for a given id naturally supersedes an earlier one via `Map.set()`, the exact last-write-wins behavior `save()` already has in memory; for `AuditLog` (append-only by nature — `record()` never updates an existing entry), rehydration just loads the ordered history back, and a new entry recorded after a restart correctly links its `previousHash` to the last pre-restart entry rather than starting a fresh chain.

**`server.ts` wires all six through one env var, `AMBIT_DATA_DIR`**, not six separate ones — `dataFile("tokens")` etc. resolves to `<dir>/tokens.jsonl` when set, `undefined` (pure in-memory, unchanged) when not.

**Two real correctness issues caught during this same piece of work, not after:**

1. **`RequestStore` must never write `tokenSecret` to disk.** ADR-013's transient, one-time-claimable token secret sits in memory on an approved-but-unclaimed `PendingRequest` — persisting it verbatim, even correctly cleared on a later line, would put the plaintext on disk, if only briefly, defeating the entire point of making it claimable exactly once. `RequestStore.save()` strips `tokenSecret` before writing to disk while still keeping it in the in-memory `Map` — the two representations genuinely diverge on purpose. Direct, named consequence: **an approved request's secret is unclaimable after a restart if it wasn't claimed before one.** No workaround exists or should — revoke the token and have the agent request a new one.
2. **The bootstrap default redaction rule was not idempotent.** `server.ts` unconditionally called `createRedactionRule(...)` for the "Standard Customer PII" rule on every boot — `createRedactionRule` always mints a fresh id, so with persistence on, every restart would have appended a *new* default rule (new id, new audit entry), silently accumulating duplicates. This is exactly the "works once but breaks on the second run" defect CLAUDE.md names as a production defect, not a nit — caught before it shipped by reasoning through what persistence would do to this specific bootstrap call, not discovered live. Fixed: reuse an existing rule named `"Standard Customer PII"` if rehydration already produced one; only create fresh on a genuinely empty store.

## Consequences

**What this closes:** ADR-009's fourth and final item. Combined with ADR-011/012/013, all four items that ADR-009 named are now closed — three for the specific routes/mechanisms each was scoped to, this one for all six stores.

**What this does not cover, named rather than hidden:**
- **No log rotation.** `AuditLog`'s persisted file grows unbounded, matching CoreOps's own base ADR-005 before its same-day rotation addendum — a real, foreseeable next step if this ever ran with enough real volume to matter, not built here.
- **No corruption recovery beyond skip-and-warn.** A crash mid-write can lose at most the one entry that was mid-write; there's no checksum or repair tool for a file corrupted some other way.
- **Still single-process, single-file per store.** No horizontal scaling story — a shared backing store would be needed at that point, not before.
- **An unclaimed token secret does not survive a restart** — named above, a deliberate consequence of never persisting it, not an oversight.

## Verification

249 tests total (20 new): `jsonlStore.test.ts` (append, rehydrate, missing-file, corrupted-line-skip, caller-revive-failure, trailing-blank-lines) plus a `persistence` describe block per store proving the real thing — a value saved before a *genuinely new store instance* (not the same object) is correctly readable after, including `TokenStore`'s revocation-supersedes-issuance case, `AuditLog`'s hash-chain-still-verifies and new-entry-links-to-pre-restart-last-entry cases, and `RequestStore`'s explicit `tokenSecret`-never-on-disk assertion (reads the raw file content directly, not just the store's own `get()`).

Live-verified against a real running server, not just unit tests: started with `AMBIT_DATA_DIR` set, created a policy, registered an agent, submitted a request, approved it, claimed the resulting token's secret, confirmed it enforced (`{"allowed":true}`) — then **killed the process outright** and restarted it against the same directory. Confirmed: the policy was still there; the audit log had the same entry count with a chain that still verified (`{"valid":true}`); the redaction-rule count stayed at exactly 1 (proving the idempotency fix); and — the real proof — enforcing the *same token with the same secret* against the restarted process still returned `{"allowed":true}`, with `secretHash` never appearing in any response.

## What would change this decision

Sustained real write volume, or a genuine need for indexed/SQL queries over any store's history, would be a reason to move to SQLite or an external database — the same threshold ADR-006 and CoreOps's ADR-005 already named. Horizontal scaling would require a shared store instead of one file per process.
