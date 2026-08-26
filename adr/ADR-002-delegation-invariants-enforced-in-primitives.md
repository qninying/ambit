# ADR-002: Delegation Invariants Enforced Inside the Primitives, Not Left as Documented Gaps

**Status:** Implemented — built, unit-tested, and live-verified over real HTTP through a two-level delegate-then-revoke chain.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-004)
**Component:** `src/token.ts` (`issueToken`, `revokeToken`), `src/delegation.ts`, `src/tokenStore.ts`

---

## Context

The initial STORY-004 proposal implemented strict-subset scope narrowing —
REQ-003's literal requirement — and explicitly flagged cascading revocation
(what happens to a delegated token when its parent is revoked) as an
out-of-scope gap to defer to a later story. The user rejected that framing
directly: a flagged gap is still a gap, and if it's a scenario that could
happen in the real world, it should be closed as part of the story that
surfaces it, not deferred to being asked again later.

Reconsidering the requirement under that standard surfaced a second, related
gap in the same category: nothing prevented a delegated child token's
`ttlSeconds` from exceeding its parent's remaining lifetime, even though a
subagent outliving the credential it was derived from is the same class of
problem as a subagent obtaining broader scope — both are a subagent ending up
with *more* authority than its parent, just measured on a different axis
(breadth vs. duration).

## Decision drivers

| Driver | Why it matters here |
|---|---|
| REQ-012's actual intent | "Zero instances of a subagent obtaining a scope broader than its parent" is a statement about authority never exceeding the parent's, and authority has more than one dimension (what it can do, how long it can do it, whether it still applies after the parent is revoked). |
| Standing user direction | Close real-world gaps found while building, don't flag-and-defer them. |
| No new call sites should be able to bypass this | If the fix lived in `delegateToken()` alone, a future caller of `issueToken()` with a `parentTokenId` set — bypassing `delegateToken()` entirely — could still produce a longer-lived child. |

## Options considered

| | **A: Flag as a known gap, fix later (original plan)** | **B: Close both gaps now, inside the primitives (chosen)** |
|---|---|---|
| Matches explicit user direction | No | Yes |
| Where the fix lives | N/A | Inside `issueToken()` (expiry cap) and `revokeToken()` (cascade), not just in `delegateToken()` |
| Can a future caller bypass it | N/A | No — the invariant is enforced at the point tokens are actually created/revoked, unconditionally |

Option A was rejected on direct instruction. The alternative to Option B — fixing
this only inside `delegateToken()` — was considered and rejected during design:
putting the expiry cap inside `issueToken()` itself means *any* future code path
that issues a token with a `parentTokenId` gets the invariant for free, rather
than depending on every future caller remembering to enforce it themselves.

## Decision

**Two invariants, enforced where tokens are actually created or revoked, not
where they're merely requested:**

1. `issueToken()` caps a delegated token's `expiresAt` to its parent's
   `expiresAt`, unconditionally, whenever a `parentTokenId` is present on the
   request — regardless of what `ttlSeconds` was asked for.
2. `revokeToken()` recursively revokes every descendant of a revoked token via
   `TokenStore.childrenOf()`, walking arbitrarily many generations (a
   sub-subagent's token included, not just direct children). Each cascaded
   revocation is logged with `reasonCode: "parent_revoked"`, distinct from a
   human-chosen reason, so the audit trail can tell the two apart.

Multi-level delegation (a subagent delegating to a sub-subagent) works without
any special-casing, since `delegateToken()` treats any active token as a valid
parent — a direct consequence of building this on ADR-001's fresh-lookup store
pattern rather than a shallow, single-level design.

## Consequences

**What this requires:** `revokeToken()` is no longer a single-write operation —
it recursively walks and rewrites the descendant subtree. At current scale
(in-memory, single process) this is cheap; it would need to be reconsidered if
delegation trees ever became deep and wide under real load.

**What this explicitly does not cover:** there is no limit on delegation depth
or fan-out (an agent could delegate to many subagents, which could each
delegate further, unbounded). That's a distinct concern — resource/rate
control on delegation itself, not an authority-broadening problem — and would
need its own decision if it became a real requirement.

## What would change this decision

A real need to bound delegation depth or fan-out (for cost, blast-radius, or
abuse-prevention reasons) would be a policy-level concern layered on top of
this, not a change to these two invariants — see ADR-004's note on the same
theme for policy-driven constraints.
