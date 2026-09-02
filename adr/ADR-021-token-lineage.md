# ADR-021: Token Lineage — Closing the Provenance Dimension

**Status:** Implemented. Closes the INPACT trust scorecard's Provenance dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/token.ts`, `src/server.ts`, `public/js/tabs/tokens/detail.js`

---

## Context

The 2026-09-01 INPACT assessment flagged Provenance as its least-confident mapping of the six dimensions and left it unscoped until the user supplied a real definition: **"the documented lineage of an AI asset, proving where it came from and how it changed."**

That maps directly onto Ambit's actual domain — the asset is a **token**. Checking what already existed before scoping anything: every token knows its immediate `parentTokenId`; every issuance and delegation is a real audit entry; revocation cascades and is logged with a reason. All the *facts* needed for a full lineage already existed. What didn't: `GET /tokens` and `GET /audit-log` have no query parameters at all, so proving one token's full lineage meant fetching everything and cross-referencing it by hand.

## Decision

**New `GET /tokens/:id/lineage`**, backed by a new `getTokenLineage()` in `src/token.ts`:

- `chain`: the full ancestry, **root-first** — walks `parentTokenId` all the way back, then returns the real, current record for every ancestor (status, revocation info included). A revoked ancestor showing its own real status and reason, right on its own link, *is* "how it changed" — no separate revocation-history structure was needed.
- `origin`: for the chain's root, the `requestId`/`policyId`/`approver` it was issued from. This is a closed, well-understood lookup, not a guess: `issueToken()` has exactly two callers in this codebase — `approveRequest()` (a root, traceable to one real `request_approved` audit entry) and `delegateToken()` (a child, possession-based, no separate human approval event). A root with no matching audit entry — shouldn't happen given that closed set — gets `origin: null` rather than a fabricated one.
- No new access control: this assembles already-public information (`GET /tokens` is already unauthenticated), and `secretHash` is stripped from every chain entry the same way `GET /tokens` already strips it.

**Console UI**: the token detail view's existing "Delegation lineage" section (which only ever showed one level — the immediate parent and immediate children, derived client-side from already-loaded state) is replaced with a real "Provenance" panel that calls the new endpoint and renders the full chain plus the origin line. Deliberately **not** reimplemented client-side from `STATE.tokens`/`STATE.auditLog` even though both are already loaded in the browser — the Console calling the real endpoint exercises the same tested assembly logic the API contract promises, rather than a second, divergence-prone reimplementation of it in JS. The one-level "delegated to" list (direct children) is kept as a separate, smaller line — descendants are a different shape of question (a tree, not a chain) and stayed out of this ADR's scope.

## Consequences

**What this closes:** Provenance's only named gap. **Provenance moves from Band 3 to Band 4 (Hardened).** New aggregate: Identity 4 + Non-repudiation 4 + Provenance 4 + Accountability 4 + Control 4 + Transparency 4 = 24/6 = **4.0/4 — all six dimensions Hardened.**

**What this does not cover:**
- No lineage view for the other five asset types (requests, policies, redaction rules, agent identities) — the trust-scorecard finding and the user's own definition both named "an AI asset," which in this system's own domain model means tokens specifically, not every persisted record.
- No descendant tree (a token's full set of children, grandchildren, etc.) — only ancestry. The Console still shows direct children separately; a full descendant tree is a different, larger feature that wasn't asked for here.

## Verification

10 new tests. `tokenLineage.test.ts` (7 — an unknown token id throws `UnknownTokenError`; a root's chain is just itself; a root's origin cites the real request/policy/approver; a root issued with no policy has `policyId: undefined`, not a fabricated one; a 3-level delegation chain renders root-first in real derivation order with the origin still correctly attributed to the root; a revoked ancestor shows its real status/reason on its own link; a cascaded revocation's reason is distinct from a direct one on the right link). `server.test.ts` gained 3 real-HTTP tests (a root's lineage over HTTP with `secretHash` confirmed stripped; a delegated token's real root-first chain over HTTP; a real `404` for an unknown id). 334/334 total passing, `tsc --noEmit` clean.

Live-verified against a real running server, not just tests: built a real 3-level chain (root → child → grandchild) over real HTTP, revoked the child for real, confirmed `GET /tokens/:id/lineage` on the grandchild showed the correct root-first chain with the child's real `compromised` reason and the grandchild's own distinct `parent_revoked` cascade reason, and the real origin (`requestId`, `approver`, no `policyId` since none was attached). Confirmed the same in the actual Console UI: the token detail view's new "Provenance" panel rendered the full chain with per-link status badges and the origin line, exactly matching the API response.

## What would change this decision

A real need to prove provenance for a different asset type (a policy's own authorship history, for instance) would be the trigger to extend this pattern beyond tokens — not scoped here since neither the original gap nor the user's own definition named it.
