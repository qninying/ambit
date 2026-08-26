# ADR-005: Audit Log Separates the Gateway's Decision From the Downstream Outcome

**Status:** Implemented — built, unit-tested, and live-verified (endpoint-down/up toggle producing the correct two-entry pattern over real HTTP).
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-005)
**Component:** `src/auditLog.ts`, `src/mockEndpointAccess.ts`

---

## Context

STORY-005 was the first story where enforcement gates something that can
itself fail independently — a mock endpoint that's reachable or not. Two
different facts exist about the same access attempt: whether the Enforcement
Gateway allowed it, and (only if allowed) what actually happened when the
system tried to reach the target. Before this story, `AuditLogEntry.decision`
only ever meant the first thing.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| These are genuinely different facts | An allowed action can still fail downstream; a denied action never gets the chance to. Conflating them loses information a real audit trail needs. |
| REQ-005/REQ-007 both apply | "Log every allowed and blocked action" (gateway) and the story's own "action and its outcome are logged" (integration) are two requirements pointing at two different moments. |

## Options considered

| | **A: Overload `decision` to also carry the endpoint outcome** | **B: Two related entries (chosen)** |
|---|---|---|
| Preserves both facts distinctly | No — a denied gateway check and an unreachable endpoint would collapse into ambiguous states | Yes — one entry per fact, joined by `tokenId`/`action` |
| Query/read simplicity | Slightly simpler (one entry per attempt) | One extra entry per successful access, but each entry is unambiguous |

Option A was rejected because it would require inventing composite decision
values (e.g. "allowed_but_unreachable") that don't compose cleanly with the
existing `"allowed" | "denied"` semantics used everywhere else in the log, and
would make "was this ever actually attempted downstream" a string-parsing
question instead of a direct field check.

## Decision

**`AuditLogEntry` gains an `outcome?: "success" | "unreachable"` field.**
`enforceToken()`'s own entry never sets it (the gateway doesn't know what
happens after it says yes). `accessMockEndpoint()` writes a **second** entry
once it actually attempts the call, with `outcome` set to the real result. A
denied gateway check never produces a second entry at all — the absence of an
outcome entry is itself informative: nothing was ever attempted.

## Consequences

**What this requires:** callers reading the audit log for "did this access
attempt fully succeed" need to check for the outcome entry's presence and
value, not just the gateway's own `decision`.

**Verified live:** toggled a mock system down mid-session, confirmed the
gateway still allowed a valid token through while the *outcome* entry came
back `"unreachable"` after the configured retries (ADR-003), then toggled the
system back up and confirmed the very next attempt produced a `"success"`
outcome entry — the two-entry pattern read correctly in both directions, not
just the happy path.

## What would change this decision

If a single access attempt ever needed more than two stages (e.g. a
multi-step downstream call with its own intermediate states), a structured
sub-log per attempt would likely replace the flat second-entry pattern — not
needed at current scope.
