# ADR-009: Trust-Boundary Hardening Deferred Until After the Platform's 12-Story Plan — Tracked Explicitly, Not Left Implicit

**Status:** Deferred by deliberate decision — not started, not forgotten. Revisit once STORY-012 lands. **Amended 2026-08-26** (same day, after STORY-009) — one narrow stopgap pulled forward per the "What would change this decision" clause below; the four-item bundle itself is still fully deferred and undiminished by it. See "STORY-009 amendment" below.
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

## STORY-009 amendment: a sharper instance, pulled forward

STORY-009's fail-closed circuit breaker (see its entry in [PROGRESS.md](../PROGRESS.md)) added `POST /circuit-breaker/simulate-outage` — a fault-injection route needed to make "the store is unreachable" demonstrable at all, since `TokenStore`/`PolicyStore` are in-memory and can't fail on their own (see [ADR-006](ADR-006-in-memory-persistence-now.md)). It was initially built with the same reasoning already applied to `POST /mock-endpoints/:system/down` from STORY-005: no auth, because it's a demo convenience.

That parallel doesn't hold up under scrutiny, and the user caught it by asking directly whether STORY-009 introduced any new weak trust boundaries. `/mock-endpoints/:system/down` only fakes a downstream integration being unavailable — it never touches real state. `/circuit-breaker/simulate-outage` disables the entire real Token & Policy Store: every enforce, issue, revoke, delegate, and policy operation, system-wide, for as long as it's left on — and because the outage flag is checked unconditionally on every attempt including the breaker's own half-open probe, the breaker never self-heals while it's set; it stays open indefinitely until someone manually clears it. This is qualitatively worse than any of the three gaps in the original Context section above: forging an approval or replaying a token at least requires a real, valid id. This route requires zero prior knowledge — one POST, no valid subject, no valid token, no valid request — to take the whole product down.

**Applied immediately, not deferred to the post-STORY-012 phase:** `requireAdminToggleKey` — a single shared-secret header check (`x-ambit-admin-key` against `ADMIN_TOGGLE_KEY`), gating only this one route. Fails closed by default: if `ADMIN_TOGGLE_KEY` isn't configured at all, the route refuses everything with a 403 rather than defaulting open. The toggle call itself is now also audit-logged (`action: "circuit_breaker_simulate_outage"`, `actor: "admin-toggle"`) as its own fact, distinct from the breaker's own organic state-transition entries — closing a second, compounding gap: previously nothing recorded that anyone had touched the toggle at all until enough real failures crossed the threshold on their own.

**This is explicitly not item 1 from the Decision section above, and does not shrink that bundle.** A single shared secret is not per-caller identity — it can't distinguish one legitimate operator from another, can't be individually revoked, and doesn't touch any of the other unauthenticated routes named in Context. All four items in the Decision section remain fully open, exactly as scoped, still deferred to the dedicated phase after STORY-012.

## STORY-010 note: a pre-existing gap widened slightly, not a new one

STORY-010 (detailed rejection error messages) added `revokedAt`/`revocationReason` fields to `Token`, and `enforceToken`'s denial messages now cite a token's real subject, scope, and timestamps by design (that's the point of the story). Checked whether this creates a new information-disclosure gap on top of the ones already named above — it doesn't: `GET /tokens`, already unauthenticated and already covered by item 1's "no caller authentication" in Context, already returns every token's complete record, including the two new fields, for free. The new detailed messages don't disclose anything an unauthenticated caller couldn't already get by listing every token. Noted here for completeness, not because it changes the Decision section's scope.

## Post-STORY-012 note: a full trust-boundary audit, two more items pulled forward

Once all 12 stories were done, the user asked for a full, systematic pass, not just per-story review. Two more items were found and closed immediately (see [PROGRESS.md](../PROGRESS.md) for the full detail); a third, larger finding — policy selection being requester-chosen rather than approver-chosen — got its own dedicated decision record, [ADR-010](ADR-010-policy-selection-moved-to-approval-time.md), since it's a real architectural choice with genuine alternatives, not a narrow stopgap.

The two pulled forward here: (1) `requireAdminToggleKey`'s comparison used plain `!==`, not constant-time — the one real secret comparison in this codebase, now using `crypto.timingSafeEqual` via a small `timingSafeStringEqual` helper (`src/timingSafeCompare.ts`). (2) Two hypotheses were chased down and *ruled out*, not assumed safe: prototype pollution via a redaction rule's `sensitiveFields` keys (verified empirically — a JSON-parsed `"__proto__"` key becomes a normal own property, and the value assigned is always a string, which the prototype setter silently rejects) and unbounded resource creation as a DoS vector (real, but already covered by the existing "no rate limiting" Tier 2 finding above, not a new item).

Same standing rule as before: neither of these small fixes substitutes for or shrinks the four-item bundle in the Decision section. All four remain fully open.
