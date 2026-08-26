# ADR-007: Single Tabbed Console, Enterprise-Density Design — Not a Consumer-App Layout

**Status:** Implemented — built, live-verified across all five tabs.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-007)
**Component:** `public/console.html`, `public/console.css`, `public/console.js`

---

## Context

Mid-build, the initial UI direction requested was: "Act as an expert frontend
developer... Build a web application layout heavily inspired by the modern
Uber interface. Focus on extreme minimalism, high contrast, and map-centric
navigation." Rather than accept that framing or only ask a clarifying
question, the recommendation made — and the standard applied since — was to
give real pushback with reasoning, per explicit user direction that this
product needs to demonstrate architectural judgment, not agreement.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| Who actually uses this, and how | An operator scanning token/policy/audit state needs to find the right row quickly and correctly. A consumer app is designed for an 8-second, low-stakes, emotional decision on a phone — the opposite shape of task. |
| Nothing in the domain is geographic | Ambit has no location data anywhere. A map would either be decorative (fake) or force in data that doesn't belong here. |
| The build's own honesty standard | Every tab elsewhere in this build shows real data or says plainly it doesn't have any — a cosmetic map with nothing real to plot on it would be the first fake thing in the whole system. |

## Options considered

| | **A: Uber-inspired, map-centric, high-contrast minimalism (as requested)** | **B: Dense enterprise-console layout (chosen)** |
|---|---|---|
| Matches the actual use case (operator scanning state) | No — optimized for a different task shape entirely | Yes — reference class is Okta's admin console, AWS IAM, Linear, Vercel's dashboard |
| Requires inventing fake data | Yes — nothing to put on a map | No |
| Signals to a technical reviewer | Reads as not having considered who uses this or what they need | Reads as understanding the actual operator workflow |

Option A was not built as requested. This was stated directly, with reasoning,
before any code was written — not silently substituted.

## Decision

**One tabbed app** (`public/console.html`) — Overview, Requests, Tokens,
Policies, Audit Log — replacing the standalone `consent.html` (now a redirect)
per a separate, related request to consolidate into a single UI rather than
per-feature pages. Dark sidebar, light dense content area, real data only, no
sample/illustrative mode anywhere in this app — unlike the Command Center
(STORY-000), which explicitly needs a sample/real toggle for a different
reason (illustrating a finished-build shape before real data exists), this
console *is* the live application, so a sample mode here would risk exactly
the kind of accidental-demo-of-fake-data this build has been built to avoid.

## Consequences

**What this requires:** every tab fetches from the real server at runtime —
verified via the Browser pane on every tab, not just asserted.

**A real bug found building this, not a hypothetical one:** the console's
background poll (refreshing every 4 seconds) could wipe an operator's open
form or in-progress typing mid-interaction. Fixed with explicit `formOpen`
state tracking plus a data-change fingerprint, so a poll only re-renders when
something has actually changed and nothing is open or focused — documented
in PROGRESS.md's STORY-007 entry in full, since it's implementation detail
rather than an architectural decision in its own right.

## What would change this decision

A genuinely geographic feature of the domain (e.g. region-scoped policies tied
to real deployment locations) would be a legitimate reason to reconsider
map-based visualization for *that specific feature* — not a reason to revisit
the console's overall layout philosophy.
