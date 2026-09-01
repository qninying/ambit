# ADR-017: TOTP MFA on Operator Login — Closing the Identity Dimension

**Status:** Implemented. Closes the INPACT trust scorecard's Identity dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/totp.ts`, `src/server.ts`, `scripts/generateTotpSecret.ts`, `public/js/chrome.js`

---

## Context

The 2026-09-01 INPACT trust-scorecard assessment named Identity's one remaining gap: `POST /auth/login` (ADR-011) is a real username/password check — scrypt-hashed, timing-safe compared, backed by a real signed session — but a single factor. Anyone who obtains (or guesses) the operator's password gets a full session with no second check. Login rate limiting, originally scoped as part of this same gap, was already closed separately by ADR-016; this ADR closes what's left.

## Decision

**TOTP (RFC 6238), hand-rolled with `node:crypto`, gating `POST /auth/login` directly — ported from CoreOps's own `totp.ts` (ADR-006), not reinvented.** Same problem (a single-operator internal tool needing a real second factor, offline, no new dependency), same right-sized answer.

- `src/totp.ts` — base32 encode/decode (RFC 4648), `generateTotpCode()` (HMAC-SHA1 + RFC 4226 dynamic truncation), `buildOtpAuthUri()` (standard Key URI for manual authenticator-app entry — no QR image generation; every mainstream authenticator app accepts manual/URI entry), and `TotpVerifier` (±1 step drift tolerance, replay protection via a tracked `lastAcceptedTimestep`). Ambit's own `#`-private-field class style, not CoreOps's `private readonly` — same primitive, matching this codebase's own idiom (`AgentIdentityStore`, `RateLimiter`).
- `POST /auth/login` now requires a third field, `totpCode`. The check is **short-circuited**, not run unconditionally: `usernameMatches && passwordMatches && totpVerifier.verify(totpCode)`. This differs from Ambit's own username/password comparison a few lines above it (which deliberately runs both checks regardless of an earlier failure) — the TOTP check has a real side effect (`verify()` burns the matched timestep against replay), so unlike a stateless string comparison, running it unconditionally would let a mistyped password consume a currently-valid code the operator still needs to actually use. This mirrors CoreOps's own `userDirectory.ts` reasoning exactly. Either a wrong password or a wrong code produces the same generic `401 invalid username, password, or authentication code` — revealing which factor was wrong would let a caller probe them separately.
- Fails closed if `ADMIN_TOTP_SECRET` is unset — same `503 authentication is not configured` treatment `SESSION_SIGNING_SECRET` already gets, extended to name the new required variable.
- `scripts/generateTotpSecret.ts` — one-time enrollment CLI, mirroring `hashPassword.ts`'s existing pattern exactly: generate, paste into env, never commit. Prints both the raw secret and a ready-to-scan `otpauth://` URI.
- `public/js/chrome.js`'s login popover gained a third field (`autocomplete="one-time-code"`, numeric, 6-digit) between password and submit.

### A stateful singleton, not a fresh-per-request read

`getSessionConfig()` reads `SESSION_SIGNING_SECRET` fresh on every request specifically so it's rotatable without a restart and testable without a separate module instance per configuration. A `TotpVerifier` can't follow that same pattern — it's stateful (`lastAcceptedTimestep` has to persist across requests for replay protection to mean anything at all); a fresh instance per request would have no memory of the last accepted code, silently disabling its own replay protection on every single call. Same tension ADR-016's `RateLimiter` already hit and solved: `getTotpVerifier()` lazily constructs and caches a `TotpVerifier`, keyed by the currently-configured secret, rebuilding only when that secret actually changes (a real rotation, or a test file's own `beforeAll` setting a different one) — not once at module load (this module is imported statically by most test files before their own `beforeAll` sets `ADMIN_TOTP_SECRET`, so an at-import-time read would always see it unset there) and not on every request either.

## Consequences

**What this closes:** Identity's one remaining named gap. **Identity moves from Band 3 to Band 4 (Hardened).** New aggregate: Identity 4 + Non-repudiation 3 + Provenance 3 + Accountability 3 + Control 4 + Transparency 3 = 20/6 = **3.33/4**, up from 3.17/4.

**What this explicitly does not cover:**
- No QR code image generation — manual/URI entry only, same tradeoff CoreOps accepted.
- No in-app enrollment flow — one-time CLI + manual authenticator-app entry only.
- No session-level MFA state and no per-decision re-verification: a valid TOTP code at login issues a normal session, good for the session's own TTL — the same accepted tradeoff CoreOps's ADR-006 named for itself, for the same reason (single-operator tool, `HttpOnly` cookies not in play here since Ambit's sessions are bearer tokens rather than cookies, but the underlying acceptance is the same: bounding exposure to a fresh-per-decision code entry is disproportionate at this scale).
- Still single-operator: one `ADMIN_TOTP_SECRET`, matching the existing single `ADMIN_USERNAME` reality.

## Verification

21 new tests: `totp.test.ts` (17 — the primitive's own logic in isolation, verified against the **published RFC 6238 Appendix B SHA1 test vectors**, not just internal generate-then-verify self-consistency) plus `totpLoginWiring.test.ts` (4 — proving the primitive is *actually wired into* `POST /auth/login`: missing code → real `400`; wrong code → the same generic `401` a wrong password gets; `ADMIN_TOTP_SECRET` unset → real `503`; and a genuine replay — the same code accepted once, then rejected on an immediate second use). The replay test needed its own isolated server (`vi.resetModules()` + dynamic import, same pattern ADR-016's `rateLimitWiring.test.ts` already established) rather than sharing `server.test.ts`'s instance — a real `TotpVerifier`'s replay protection means only one login can succeed per 30-second step anywhere in the process, so a shared, already-logged-in server would make the "first call succeeds" half of that test fail before it even started.

`server.test.ts`'s own shared-server suite calls `login()` dozens of times; its `login()` helper is now memoized after the first real call rather than performing a fresh HTTP request each time, for the same reason — a fresh call per test would generate the identical code (same 30-second step) and every call after the first would be rejected as a replay. One genuine login proves the wire path works; every other test in that file just needs *a* valid session, the same way a real operator doesn't re-login for every single API call either.

289/289 total passing, `tsc --noEmit` clean.

Live-verified against a real running server, not just tests: generated a real secret and password hash, started the server, logged in through the actual Console UI with a freshly-computed real code — the auth widget correctly showed "Signed in as demo-verify-operator" and the network log showed a real `200` from `POST /auth/login`. Then, over `curl` against the same running instance: replaying that exact same code got a real `401`; omitting `totpCode` entirely got a real `400`.

## What would change this decision

- **A second real operator** — this design assumes one secret for one person; multi-user MFA needs per-user secret storage, not a second env var.
- **Compliance requirements for phishing-resistant MFA specifically** — TOTP is vulnerable to real-time phishing (a fake login page relaying a stolen code immediately) in a way WebAuthn is not. Not a real threat model for a single-operator portfolio demo today; would be the correct trigger to revisit if that changes.
