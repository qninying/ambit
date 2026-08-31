# ADR-011: Real Operator Authentication — First Slice of the ADR-009 Hardening Phase

**Status:** Implemented for `POST /requests/:id/approve` and `POST /requests/:id/deny` only. Every other route remains unauthenticated — see Consequences.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-31
**Component:** `src/passwordHash.ts`, `src/sessionToken.ts`, `src/server.ts`, `public/console.js`, `scripts/hashPassword.ts`

---

## Context

ADR-009 named "real caller authentication" and "a verified approver identity" as two of its four still-open items, explicitly deferring the concrete design ("what does 'closed' mean for a portfolio demo, not an enterprise IdP integration") to when this phase actually started. This ADR is that phase's first real slice: an operator now has to log in for real, and `approver` on an approval or denial is derived from that authenticated session — never a string the client sends.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| Right-sized for what this actually is | Ambit has one operator role today, not a multi-tenant org with a real IdP to federate against. Building for that shape now would be solving a problem this system doesn't have. |
| No new dependency without a deliberate reason | Same standard held everywhere else in this build — a JWT library or a password-hashing package would each replace something `node:crypto` already does completely for this scope. |
| The fix has to be structurally real, not cosmetic | "Verified approver identity" only means something if the server derives it from something it verified, not from a field with a different name that's still client-supplied. |

## Options considered

| | **A: Full IdP/OAuth2 integration** | **B: A JWT library + a real user database** | **C: Hand-rolled signed sessions over a single configured operator account (chosen)** |
|---|---|---|---|
| Matches what Ambit actually is today | No — massive overbuild for a single-operator demo | Partially — still assumes multiple users this system doesn't have | Yes |
| New dependencies | Yes — an OAuth/OIDC client library at minimum | Yes — `jsonwebtoken` or similar, plus likely a hashing library | None — `node:crypto` covers scrypt hashing, HMAC signing, and constant-time comparison completely |
| Real (not theatrical) authentication | Yes | Yes | Yes — a real password check (scrypt, salted, constant-time) and a real signed, expiring session, not a shared header string |

Option A was ruled out immediately as solving a problem this system doesn't have. Option B was closer, but the actual cryptographic surface needed — sign a small payload, verify it, check an expiry, hash and verify one password — is small enough that pulling in a library for it would be adding a dependency to save writing about 100 lines of code this build has already shown it holds itself to writing correctly elsewhere (`timingSafeCompare.ts`, the hash chain in `auditLog.ts`).

## Decision

**`src/passwordHash.ts`**: `hashPassword`/`verifyPassword` using `node:crypto`'s `scrypt` (deliberately slow and memory-hard, salted, constant-time comparison via `timingSafeEqual`). **`src/sessionToken.ts`**: a minimal signed token — `base64url(JSON payload).HMAC-SHA256 signature` — verified signature-first, before the payload is ever trusted or parsed, so a tampered payload never gets read. **One operator account**, configured via `ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH` (generated with `npm run hash-password`, so the raw password is never the thing that ends up in an env var) + `SESSION_SIGNING_SECRET` (no default — auth fails closed, 503, if unset, rather than ever signing with a guessable fallback). All three read fresh per-request (`getSessionConfig()`), same reasoning as `requireAdminToggleKey`'s `ADMIN_TOGGLE_KEY`: rotatable without a restart, and testable without a separate module instance per configuration — this was a real bug caught during this same piece of work (see PROGRESS.md), not a decision made cleanly the first time.

`POST /auth/login` verifies username (timing-safe) and password (scrypt), issues a session token. `requireSession` middleware verifies the `Authorization: Bearer <token>` header and attaches `req.session = {username}`; never throws — a missing or invalid session is a clean 401, matching this codebase's established "never crash, always a decision" contract for gateway-shaped checks. **`approver` is deleted from `POST /requests/:id/approve` and `POST /requests/:id/deny`'s accepted body fields entirely** — it comes from `req.session.username`, full stop, even if a client sends a different value in the body (verified directly: a real HTTP test asserts the audit trail shows the authenticated username, not a claimed one).

The Console (`public/console.js`) gained a real login widget in the sidebar (visible on every tab, not just Requests), a session token in `localStorage` (a per-viewer convenience, not itself a security boundary — the server's own verification is), and a fix to `formFieldIsFocused()` — the login form lives outside `#tab-content`, so the existing poll-safety guard didn't originally protect it from a background refresh wiping mid-typed credentials, a real gap caught during live verification, not assumed safe.

## Consequences

**What this actually closes:** approve and deny now have a real, verified approver identity. That's genuinely ADR-009 item 2, for those two routes.

**What this does NOT close — stated plainly, not implied by the ADR's title:** every other mutating route — `POST /tokens/:id/revoke`, `POST /policies`, `PATCH /policies/:id`, `POST /redaction-rules`, `POST /tokens/:id/delegate`, request submission itself — remains completely unauthenticated. ADR-009's item 1 ("real caller authentication on every route") is not closed by this ADR; only its most identity-critical corner is. Token possession proof (item 3) and real persistence (item 4) are untouched. `req.session.username` also isn't yet used as an authorization boundary beyond "some operator is logged in" — there's no role/permission distinction between operators, because there's only one operator account to have one.

## What would change this decision

If Ambit ever needed more than one distinct human operator (not just "the" admin), the single-account model here would need to become a real user store — at that point, revisit whether the hand-rolled approach still holds or whether the added complexity finally justifies a real auth library.
