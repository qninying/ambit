# Ambit — Identity and Access Management for AI Agents

Ambit issues short-lived, narrowly-scoped tokens for autonomous AI agents,
requires a real human to approve every request before a token exists, and
enforces that a subagent can never end up with more authority — broader
scope, longer life, or continued validity after its parent is revoked — than
the credential it was derived from. Every allowed action, every denial, every
policy change, and every administrative action is logged to an audit trail
that's hash-chained end to end, so "immutable" is a property you can check,
not just a claim in a comment.

See [`adr/`](adr/) for the real architectural decisions behind this — what was
considered and rejected, not just what shipped.

## See it running

```bash
npm install
npm run start
```

Then open `http://localhost:4000/console.html` — a live admin console
(Overview, Requests, Tokens, Policies, Audit Log) reading real data from the
running server, not sample data. Submit a token request, approve or deny it,
watch a real token appear in the Tokens tab, revoke it, and see the whole
sequence land in the Audit Log with its chain-verified badge.

## What's real

Every claim below has a test behind it and was verified against the real
running server — over `curl` and through the Browser pane, not just asserted
in a unit test. Current count: **125 tests passing.**

**Token lifecycle**
- Short-lived, scoped token issuance (`issueToken`) with strict input
  validation — no token is ever issued already expired or with empty scope.
- Real-time revocation: `revokeToken` writes straight into the store all
  reads go through, so the very next lookup by id sees the new state — no
  window where a stale in-flight copy still works.
- Delegation that can only narrow: a subagent's scope must be a *strict*
  subset of its parent's (requesting the exact same scope back is denied,
  not accepted), its expiry is capped to its parent's regardless of what TTL
  was requested, and revoking a token cascades recursively through every
  descendant it delegated to, multi-level.
- Every denial from the Enforcement Gateway carries a genuinely detailed
  message, not just a terse code — citing the token's real scope for
  `out_of_scope`, its real issue/expiry timestamps for `expired`, and the
  real time and reason it was revoked for `revoked`. An allowed decision
  carries no message field at all. The audit log records the same detail,
  not just the code.

**Human oversight**
- Every token request sits pending until a human approves or denies it via
  the Consent flow — `issueToken()` only ever runs on approval, never on
  submission.
- Human-authored policies constrain what a token can be issued with, checked
  fresh on every issuance — editing a policy changes what the *next*
  issuance allows, proven by re-issuing after modifying, not by inspecting a
  stored record.

**Client SDK**
- [`sdk/ambitClient.ts`](sdk/ambitClient.ts) — `AmbitClient`, the thing an
  external developer actually imports: `requestToken()`, `getRequest()` to
  poll for a decision and the resulting token id, a typed `AmbitClientError`
  on any failure. A submission carrying a caller-supplied `idempotencyKey`
  is safe to retry — the server dedupes on `(subject, idempotencyKey)`
  rather than creating a second request — so the SDK's own capped-retry
  loop can recover from a lost response without a duplicate submission; a
  4xx (an invalid request) is never retried, since a retry can't fix that.
  Verified against a real ephemeral-port server in tests and, separately,
  against the live dev server from a standalone script.

**Trust and observability**
- Anomaly detection (unusual scope breadth, request velocity) on every
  submission, automatically, with configurable — not hardcoded — thresholds.
- Mock endpoint integration (email, code hosting, payment, CRM) reachable
  only through the Enforcement Gateway, with a real timeout-and-capped-retry
  wrapper around the downstream call.
- A hash-chained audit log: every entry's hash covers its own content plus
  the previous entry's hash, so altering or deleting any entry is detectable,
  not just discouraged by convention. `GET /audit-log/verify` and the
  Console's Audit Log tab both expose this live.
- A fail-closed circuit breaker (`src/circuitBreaker.ts`) in front of the
  Token & Policy Store: closed → open after consecutive failures → half-open
  probe after a cooldown → closed again on success. While open, `enforceToken`
  and `delegateToken` return a clean denial (`store_unavailable`) rather than
  crashing; `issueToken`/`createPolicy` fail loud with a 503, never a silent
  success. `GET /circuit-breaker` for live state, `POST
  /circuit-breaker/simulate-outage` to actually trip it — the store is
  in-memory and can't fail on its own (see below), so this is what makes
  the fail-closed behavior demonstrable rather than asserted. Unlike every
  other route in this API, `simulate-outage` requires a shared-secret
  `x-ambit-admin-key` header (set `ADMIN_TOGGLE_KEY` to enable it — refused
  by default otherwise): it's the one route that can take the entire real
  Token & Policy Store down with a single unauthenticated request, so it got
  a narrow stopgap pulled forward ahead of the rest of
  [ADR-009](adr/ADR-009-trust-boundary-hardening-deferred-to-post-platform-phase.md)'s
  deferred hardening work.

**What's explicitly not real yet:** persistence. Everything above resets on
a server restart — an in-memory `Map`-backed store, chosen deliberately (see
[ADR-006](adr/ADR-006-in-memory-persistence-now.md)) rather than left as an
accident. Every store's interface is shaped so a real backing store could
replace it later without touching a single caller.
