# ADR-015: Control Hardening, First Slice — Authenticating the Remaining Management Routes

**Status:** Implemented for `POST /policies`, `PATCH /policies/:id`, `POST /redaction-rules`, `POST /tokens/:id/revoke`. Rate limiting (the second half of this Control-hardening initiative) shipped separately as [ADR-016](ADR-016-rate-limiting.md) — together the two close Control to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/token.ts`, `src/server.ts`, `public/js/state.js`, `public/js/chrome.js`, `public/js/tabs/policies.js`, `public/js/tabs/redactionRules.js`, `public/js/tabs/tokens/detail.js`

---

## Context

Ambit's first INPACT trust-posture scorecard (2026-09-01) scored Control at Band 2, the lowest of six dimensions — four routes accepted requests from anyone, no login required at all: `POST /policies`, `PATCH /policies/:id`, `POST /redaction-rules`, `POST /tokens/:id/revoke`. This is the first of two planned steps to close that gap (the second is rate limiting), scoped deliberately narrow so each piece ships as a complete, verified change rather than one large one.

## Decision

**All four routes now require `requireSession`** — the exact middleware ADR-011 already built for approve/deny, applied to four more routes rather than reinvented. `authoredBy` on policies and redaction rules is now derived from `req.session!.username`, same treatment ADR-011 gave `approver` and ADR-012 gave `subject`: a client-supplied `authoredBy` in the request body is silently ignored.

**Revocation gained an `actor`**, which it never had before this — `revokeToken()` took no actor parameter at all, so a revocation's audit entry recorded *that* something was revoked and why, but never *who* did it. `actor` is optional at the primitive level (every existing direct caller — tests, other internal code — keeps working unchanged) but the real HTTP route always supplies it now. Cascaded child revocations get the same actor as the parent: they're a direct, deterministic consequence of that one human's action, not a separate decision, so attributing them to a generic "system" would be less accurate, not more neutral.

**Revocation is deliberately still not possession-checked** — ADR-013's own scoping holds: revoking is a management action, not a use of the token's own authority, and an operator revoking a leaked credential may no longer hold that secret at all. What changed here is *who* can revoke (a real operator), not *what proof of the token itself* is required (none, unchanged).

**Two real gaps caught while building this, not after:**

1. **`patchJson()` never attached a session token at all**, unlike `postJson()`. Harmless while nothing PATCH-based required one — a real, silent break the moment `PATCH /policies/:id` did. Fixed to match `postJson()`'s attach-and-clear-on-401 behavior exactly.
2. **The Console's "Acting as" free-text control became dead UI**, not just unused code. It fed `authoredBy` on exactly the two routes now deriving that field from a real session — leaving it in place would mean a control that visibly does nothing, which is a UI lie, not a harmless leftover. Removed entirely: `public/js/session.js` deleted, its CSS rules removed, `chrome.js`'s topbar no longer renders it. Policies and Redaction Rules tabs gained the same "not signed in" banner and "log in first" client-side guard already established in `requests.js`, plus a line stating plainly whose identity will actually be recorded.

## Consequences

**What this closes:** the four routes named in Context now require a real, verified operator identity, and that identity — not a client-supplied string — is what lands in the audit trail.

**What this does not close on its own:** at the time this ADR shipped, Control was not yet at Band 4 — rate limiting (the second half of this initiative) followed separately as ADR-016, and the two together are what actually closes the dimension. `POST /agent-identities`/`GET /agent-identities` were already session-gated before this ADR (ADR-012) and are unaffected. `POST /requests` remains gated by agent credential, not operator session, unaffected (ADR-012's own scope, a different kind of caller).

## Verification

Backend: 260/260 tests passing (11 new — `revokeToken.test.ts`'s actor-attribution coverage including the cascade case, and a new `server.test.ts` "ADR-015" block proving 401-with-no-session and correct-actor-derivation over real HTTP for all four routes). `tsc --noEmit` clean.

Live-verified end to end in the Browser pane against a real running server, not just unit tests: confirmed the Policies tab shows "not signed in" and refuses to submit while logged out; logged in for real; created a policy and confirmed `AUTHORED BY` showed the real username; edited it (proving the `patchJson` fix) and confirmed the change landed; created a redaction rule and confirmed the same real-identity attribution; registered an agent, submitted and approved a real request, and revoked the resulting token through the UI — confirmed the audit log's own rendering showed `revoke-test-agent via control-verify` and the chain still verified. Zero console errors throughout.

## What would change this decision

If Ambit ever needed more than one distinct human operator, the "who can do this" question stays the same (any real operator session suffices) — that's an Accountability concern (a second approver, escalation), not a Control one, and is tracked separately in the trust scorecard roadmap.
