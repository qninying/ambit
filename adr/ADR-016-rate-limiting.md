# ADR-016: Rate Limiting — Second and Final Slice of Control Hardening

**Status:** Implemented. Closes the INPACT trust scorecard's Control dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/rateLimiter.ts`, `src/server.ts`, `vitest.config.ts`, `vitest.setup.ts`

---

## Context

ADR-015 closed the first half of the Control gap (four unauthenticated management routes) and named the second half explicitly: nothing in Ambit stopped repeated requests. `POST /auth/login` accepted unlimited password guesses; no route had any flood protection at all — a real, verified gap (grepping the repo for rate limiting turned up nothing before this).

## Decision

**Ported CoreOps's own `rateLimiter.ts` nearly verbatim** — a fixed-window, in-memory, per-key counter with an injectable clock — rather than reinventing the mechanism or pulling in a dependency. Fixed window (not sliding/token-bucket) is deliberate: Ambit is a single-operator portfolio demo, not a public API under adversarial load-shaping pressure. A fixed window's known boundary-burst quirk (up to 2x the limit right at a window edge) is an acceptable tradeoff for the actual threat model — a scripted brute-force loop, not an attacker specifically evading rate-limit windows.

**Two limiters, not one.** A general one (`120` requests / `60s` default) as a basic flood backstop across the API, and a deliberately stricter one (`5` requests / `60s` default) on `POST /auth/login` specifically — the one route where a tight limit closes a real brute-force gap rather than just generic abuse protection. Both keyed by `req.socket.remoteAddress`, not `X-Forwarded-For` — Ambit has no reverse proxy in front of it in any deployment this repo targets, so the socket address is the real, unspoofable client address rather than a header a caller could set themselves. Both thresholds overridable via env vars (`RATE_LIMIT_GENERAL_MAX_REQUESTS`/`RATE_LIMIT_GENERAL_WINDOW_MS`/`RATE_LIMIT_LOGIN_MAX_REQUESTS`/`RATE_LIMIT_LOGIN_WINDOW_MS`), same "not hardcoded" treatment as every other judgment-call threshold in this codebase.

**The general limiter sits after `express.static`, not before** — a normal Console page load fetches several JS/CSS files, and none of that should count against API flood protection. Placed after, a matched static-file request never reaches the limiter at all; only requests that fall through to the real API routes do.

**A real testability wrinkle, solved with a Vitest setup file, not a workaround in `server.ts` itself.** Unlike `getSessionConfig()` (deliberately read fresh per-request specifically so tests can reconfigure it), a `RateLimiter` is stateful — it has to keep its counts across requests, so its *thresholds* can only be set once, at construction. That's fine for production, but `server.test.ts` alone makes over twenty real `login()` calls across its test run — comfortably enough to trip the real 5/60s login default if the whole suite shared it, before a single test's actual behavior was even being checked. `vitest.setup.ts` sets both `RATE_LIMIT_*_MAX_REQUESTS` env vars to a very high number (`??=`, so any test file that deliberately wants the tight default can still override it) before any test file's module graph loads — this changes nothing about what ships, only what the test run itself experiences.

## Consequences

**What this closes:** the Control dimension's second and final named gap. Combined with ADR-015, **Control moves from Band 2 to Band 4 (Hardened)** — closing four unauthenticated routes and adding rate limiting was the specific, complete definition of this gap from day one, not a partial fix.

**What this does not cover:** the general limiter is a basic flood backstop, not tuned against a real production traffic profile (this system has none). No distributed rate limiting — a horizontally-scaled deployment would need a shared store (Redis or similar) instead of in-memory per-process counters, the same class of limitation ADR-006/014 already named for the other stores.

## Verification

8 new tests: `rateLimiter.test.ts` (6, the class's own logic in isolation — allows-under-limit, blocks-at-limit, `retryAfterMs` bounded correctly, resets after the window elapses, doesn't reset a moment early, independent keys tracked separately) plus `rateLimitWiring.test.ts` (2, proving the class is *actually wired into* `server.ts`, not just correct on its own — a real HTTP 429 with a real `Retry-After` header once a deliberately tight limit is hit, for both the general limiter and, separately, the stricter login one, each via its own dynamically-imported server instance so their different thresholds don't collide). 268/268 total passing, `tsc --noEmit` clean.

Live-verified against a real running server with production-default thresholds, not just tests: sent 7 real `POST /auth/login` requests with a wrong password — the first 5 got real `401`s (reaching actual auth logic, each logged to the audit trail as `login`/`denied`/`invalid_credentials`), the 6th and 7th got a real `429` with `Retry-After: 60`. Confirmed the block applies even to the *correct* password once the limit is hit (proving it's genuinely a per-IP request count, not a credential check short-circuiting) — and confirmed the two blocked attempts correctly left **no** audit trace at all, since they never reached the login handler to begin with.

## What would change this decision

Sustained real traffic, or a genuine need to distinguish legitimate bursts from abuse more precisely, would be a reason to move to a sliding-window or token-bucket algorithm. Horizontal scaling would require a shared store for the counters, the same threshold CoreOps's own `rateLimiter.ts` names for itself.
