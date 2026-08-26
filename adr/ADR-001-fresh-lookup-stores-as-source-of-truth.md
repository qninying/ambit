# ADR-001: Fresh-Lookup Stores as the Single Source of Truth

**Status:** Implemented — built, unit-tested, and live-verified over real HTTP.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-002)
**Component:** `src/tokenStore.ts`, `src/requestStore.ts`, `src/policy.ts`

---

## Context

The first design proposed for STORY-002 (real-time revocation) had `revokeToken()`
return an updated `Token` object, with the caller expected to re-check that
returned value on the next call. That design would have made the acceptance
criterion — "a revoked token's next call fails within the same request cycle" —
pass in a test, because the test would naturally use the freshly-returned object.
It would not have made it *true*: any other caller still holding an earlier copy
of the same token would keep succeeding against a value that revocation never
touched. The mechanism would look real and not be real.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| REQ-015 must be actually true, not just testable | A revoked token's next call has to fail regardless of which copy a caller happens to be holding — the guarantee is about the system's state, not about one variable's lifetime. |
| Consistency across every mutable entity | Tokens, pending requests, and (later) policies all have the same shape of problem: something issued now, decided on later, by a different caller. |
| No premature infrastructure | This is a walking skeleton — the fix needed to be a design pattern applicable in-process, not a reason to reach for a database this early. |

## Options considered

| | **A: Pass-by-value between functions** | **B: Fresh-lookup store (chosen)** | **C: Event-sourced log with rebuild-on-read** |
|---|---|---|---|
| Guarantees "next call sees the new state" | No — only if every caller happens to re-fetch, which nothing enforces | Yes — every read goes through `get(id)` against live state | Yes, but by replaying history each time |
| Implementation cost | Lowest, but the guarantee is an illusion | Small — a `Map`, `get`/`save` | Larger — needs an event schema and replay logic before it does anything a plain store doesn't |
| Matches current scale | N/A | Yes | Overkill for single-process, in-memory state |

Option A was rejected outright once the actual requirement was restated plainly:
"the next call" means *any* next call, not just the one holding the newest
reference. Option C was rejected as solving a problem this system doesn't have
yet — there is no requirement here for historical replay or point-in-time
reconstruction, only for current-state correctness.

## Decision

**`TokenStore`, `RequestStore`, and `PolicyStore` are the single source of truth
for their respective entities.** Every store follows the same shape: `save(x)`,
`get(id)`, and where needed `list()`/`childrenOf(id)`. `enforceToken()`,
`revokeToken()`, and `delegateToken()` all take an **id**, never a `Token`
object, and re-read the store fresh on every call — a caller cannot pass a stale
copy and get a stale answer, because there is no code path that accepts one.

## Consequences

**What this requires:** every mutation writes back through `store.save()`
immediately — there is no "compute now, persist later" step anywhere in the
codebase for these three entities.

**What this does not cover:** the stores are in-memory (`Map`-backed), single
process. See ADR-006 for why that's a deliberate, not accidental, choice, and
what would change it.

## What would change this decision

Horizontal scaling of the server process would require these stores to become
shared (a real database or cache) rather than local in-process `Map`s — the
`get`/`save` interface is deliberately shaped so that swap wouldn't require
touching any caller.
