# ADR-009: Trust-Boundary Hardening Deferred Until After the Platform's 12-Story Plan — Tracked Explicitly, Not Left Implicit

**Status:** Deferred by deliberate decision — not started, not forgotten. Revisit once STORY-012 lands.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26
**Component:** `src/server.ts`, `src/tokenRequest.ts`, `src/token.ts`, `sdk/ambitClient.ts`, every route in `src/server.ts`

---

## Context

A direct audit of the running system (grep across `src/`, `sdk/`, `public/` — not a guess) found that Ambit's control-plane API has no caller authentication of any kind: no bearer tokens, API keys, sessions, or JWTs anywhere in the codebase. Three specific consequences of that, in order of how much they undercut the product's own premise:

1. **`approver` is a free-text string the caller supplies in the request body** ([server.ts:95-97](../src/server.ts#L95), [server.ts:115-118](../src/server.ts#L115)). REQ-002/REQ-013's entire promise — "a real human approves every request" — rests on an assertion nothing verifies. The agent whose own request is pending could approve itself by calling the API directly and claiming to be the approver.
2. **Tokens are bearer-by-UUID with no possession proof.** No signing (JWT/HMAC), no client secret, no mTLS. Knowing or guessing a token id is functionally equivalent to holding it, and there is no TLS anywhere in this stack to even protect the id in transit.
3. **No route in `src/server.ts` authenticates who is calling it at all** — `POST /tokens/:id/revoke`, `POST /policies`, `POST /tokens/:id/delegate`, all of it, is open to anyone who can reach the port.

Checked against `docs/stories/STORY-009.md` through `STORY-012.md` (circuit breaker, detailed rejection errors, field-level redaction, distinct denial reason codes) before writing this: **none of the platform's remaining four stories touch this.** As scoped, the 12-story plan completes without ever answering "who is allowed to call this API in the first place." That is not a story-writer oversight to wait out — it will still be true after STORY-012 unless something outside the plan closes it.

A related, compounding gap named honestly elsewhere already (not new here, restated for completeness): [ADR-006](ADR-006-in-memory-persistence-now.md)'s in-memory persistence means the entire system — including the hash-chained, tamper-evident audit log from [ADR-008](ADR-008-hash-chained-tamper-evident-audit-log.md) — evaporates on restart. An audit trail that is provably tamper-evident but does not survive a restart is the same category of "not actually legit to the pitch" as an approval nothing verifies.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| Don't mix unrelated scope into the platform's tracked stories | STORY-009-012 each have a specific acceptance criteria set the Command Center reads from `.colaberry/progress.json`. Threading authentication work into those commits would make each story's own verification harder to trust, not easier. |
| Don't let "later" mean "never" | This build has already had one close call with a concurrent session altering repo state. A commitment that lives only in a chat transcript is one compaction away from disappearing. This ADR is the durable form of that commitment. |
| Realistic sizing, stated up front | Authentication, token possession proof, and a real approver identity touch nearly every route and several existing tests. This is not a 30-minute bolt-on at the end — treating it as one would just produce a second, rushed version of the same shortcut problem this build has repeatedly caught and rejected elsewhere. |

## Options considered

| | **A: Interleave hardening into STORY-009–012 now** | **B: Skip it entirely, ship as-is** | **C: Defer to a dedicated post-platform phase, tracked explicitly (chosen)** |
|---|---|---|---|
| Keeps each remaining story's own scope legible | No — every story's diff would carry unrelated auth plumbing | N/A | Yes |
| Demo eventually matches its own pitch | Possibly, but at the cost of (A)'s scope-mixing | No — the gap stays open indefinitely, and "IAM system with no access control on itself" is discoverable by any reviewer in under a minute | Yes, on a committed timeline |
| Risk of silently never happening | Low, but only because it's forced into scope now | Certain | Mitigated by this document existing — the standing risk with "later" plans, closed the same way ADR-006 already closes it for persistence |

Option A was rejected specifically because of the "no gaps deferred" standard this build has held itself to elsewhere (see [ADR-002](ADR-002-delegation-invariants-enforced-in-primitives.md), where a similar shortcut proposal was rejected mid-story) — the fix here is not to defer *quality*, it's to sequence *scope* correctly so the platform's own tracked work stays clean. Option B was never seriously on the table; an unauthenticated IAM control plane is the single most damaging thing a technical reviewer could find.

## Decision

**Trust-boundary hardening is scoped as one deliberate phase, started immediately after STORY-012 lands, bundling all of the following together** (not split across separate later passes, since a hardened-but-not-durable system and an authenticated-but-still-in-memory audit log are each still not "legit to the pitch" on their own):

1. Real caller authentication on every route in `src/server.ts`.
2. A verified approver identity replacing the free-text `approver` field — REQ-002/REQ-013 don't mean anything without this.
3. Token possession proof (signed or otherwise bound tokens, not raw UUIDs looked up by string equality).
4. Real persistence for every store, closing the ADR-006 gap in the same pass rather than as a separate afterthought.

**What "closed" concretely means — full enterprise IdP/mTLS integration vs. a right-sized scheme for a portfolio demo — is explicitly not decided by this ADR.** That is a real design call to make deliberately when this phase starts, not to default into by momentum.

## Consequences

**What this requires:** nothing changes in the codebase today. This document is the commitment mechanism — it is checked back into git specifically so it survives a session boundary, a compaction, or a different Claude Code instance picking up this repo.

**What this does not do:** it does not make the current API safe to expose beyond a local/trusted-network demo context in the meantime. Every route documented above stays open exactly as it is until this phase actually starts.

## What would change this decision

A demo audience or reviewer with direct API access before this phase starts would be a real reason to pull a minimal slice of Tier 1 forward — at minimum, item 2 (verified approver identity) — rather than wait for the full bundle.
