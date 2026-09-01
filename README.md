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
(Overview, Requests, Tokens, Policies, Redaction Rules, Audit Log, System)
reading real data from the running server, not sample data. Submit a token
request, then log in to approve or deny it (see below), watch a real token
appear in the Tokens tab, delegate a narrower child token from it, access a
demo customer record and watch field-level redaction happen live, revoke it,
and see the whole sequence land in the Audit Log with its chain-verified
badge. ⌘K opens a command palette to jump between sections; the theme toggle
switches light/dark, both persisted per-browser.

Approving or denying a request needs a real operator login:

```bash
npm run hash-password -- 'pick-any-password'
# then, with the printed hash:
ADMIN_USERNAME=admin ADMIN_PASSWORD_HASH='<the printed hash>' SESSION_SIGNING_SECRET='any-long-random-string' npm run start
```

To survive a restart (see [ADR-014](adr/ADR-014-persistence-via-append-only-jsonl.md)), add `AMBIT_DATA_DIR=./data` — every store writes append-only JSONL there; unset, everything stays in-memory as before.

## What's real

Every claim below has a test behind it and was verified against the real
running server — over `curl` and through the Browser pane, not just asserted
in a unit test. Current count: **260 tests passing.**

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
- Every denial across the system carries a distinct, correct `reasonCode`
  — enforced structurally, not just by convention: `AuditLog.record()`
  itself refuses to accept a `"denied"`/`"request_denied"` entry with no
  `reasonCode`, so a future denial path can't silently ship without one.
  Human denials (`POST /requests/:id/deny`) require one of a closed set of
  reasons, same treatment as `revokeToken`'s own reason codes.

**Field-level redaction**
- `src/customerDataAccess.ts` gates customer-data access through the same
  Enforcement Gateway as everything else, then applies field-level
  redaction on top: a `RedactionRule` maps each sensitive field to the
  *specific* scope required to see it unredacted, so a token can hold
  baseline `customer:read` and see one field elevated (e.g. `ssn`) while
  everything else in the rule stays masked. A redaction rule id that can't
  be resolved denies the whole request rather than falling back to
  unredacted data. The server always applies its own configured rule — a
  caller cannot select which rule grades their own request, even via the
  request body, specifically because that would let an unauthenticated
  `POST /redaction-rules` call craft a rule weak enough to defeat itself.

**Human oversight**
- Every token request sits pending until a human approves or denies it via
  the Consent flow — `issueToken()` only ever runs on approval, never on
  submission.
- Human-authored policies constrain what a token can be issued with, checked
  fresh on every issuance — editing a policy changes what the *next*
  issuance allows, proven by re-issuing after modifying, not by inspecting a
  stored record.
- Which policy governs an approval is the *approver's* choice, made at
  approval time — never something the requester pre-selects on their own
  submission (see [ADR-010](adr/ADR-010-policy-selection-moved-to-approval-time.md)).
  A requester citing their own policy would make "policy attached" a
  self-issued rubber stamp; the audit trail records exactly which policy an
  approver applied, not just that one was.
- Approving or denying a request requires a real, authenticated operator
  session — `POST /auth/login` checks a scrypt-hashed password and issues a
  signed, expiring token (`src/sessionToken.ts`, no JWT library — `node:crypto`
  covers it completely); `approver` in the audit trail comes from that
  session, never from a field the client sends (see
  [ADR-011](adr/ADR-011-real-operator-authentication-first-slice.md)).
  **Scoped honestly, not implied broader than it is**: this was the first
  slice of [ADR-009](adr/ADR-009-trust-boundary-hardening-deferred-to-post-platform-phase.md)'s
  hardening phase; policy management, redaction rules, and revoke are now
  also session-gated (see below and
  [ADR-015](adr/ADR-015-control-hardening-first-slice.md)) — delegation and
  request submission were closed separately by ADR-012/013.
- Submitting a token request requires a real, registered agent credential —
  `POST /requests` no longer accepts `subject` as a plain client-supplied
  field at all; it's derived server-side from an `Authorization: Bearer
  <id>.<secret>` credential (`src/agentIdentity.ts`, scrypt-hashed at rest,
  looked up by id then verified, same pattern as operator passwords). An
  operator mints agent identities via `POST /agent-identities`, one-time
  credential returned at registration only (see
  [ADR-012](adr/ADR-012-agent-caller-authentication-second-slice.md)).
  **Scoped honestly**: this closes [ADR-009](adr/ADR-009-trust-boundary-hardening-deferred-to-post-platform-phase.md)
  item 1 for `POST /requests` only — there's no revoke/rotate path yet for a leaked agent
  credential.
- Using an issued token — to enforce it, delegate from it, reach a mock
  endpoint, or read customer data through it — requires proving you hold
  its real secret, not just knowing its (public, widely-visible) id.
  Checked inside `enforceToken()` itself, before any other detail about the
  token is disclosed, so a wrong credential also stops leaking a token's
  real status for free. A human-approved token's secret is claimed exactly
  once by the original requesting agent (`POST /requests/:id/token-secret`,
  gated by the same agent credential it submitted with); a delegated
  token's secret is handed back synchronously to whoever just proved they
  held the parent (see
  [ADR-013](adr/ADR-013-token-possession-proof.md)). **This closes ADR-009
  item 3** for the four routes that actually exercise a token's authority
  — `POST /tokens/:id/revoke` is deliberately not possession-checked
  against the token's own secret (an operator revoking a leaked credential
  may no longer hold it), though it does require a real operator session
  (see below).
- `POST /policies`, `PATCH /policies/:id`, `POST /redaction-rules`, and
  `POST /tokens/:id/revoke` all require a real operator session —
  `authoredBy` on policies/redaction-rules and `actor` on a revocation
  (including every child revocation it cascades to) come from that session,
  never a client-supplied field (see
  [ADR-015](adr/ADR-015-control-hardening-first-slice.md)). **Scoped
  honestly**: this is the first of two planned steps closing the INPACT
  trust scorecard's Control gap — rate limiting (the second step) is not
  yet built, so nothing stops hammering `/auth/login` or any other route
  with repeated requests.

**Console**
- Every backend capability above has a real UI surface, not just an API —
  including delegation, redaction-rule authoring, and customer-data access,
  which previously existed only as tested backend logic with nothing wired
  up to see them. The Tokens tab's token-detail view has inline "Delegate a
  narrower token" and "Access customer data" panels calling the real
  `POST /tokens/:id/delegate` and `POST /tokens/:id/customer-data/:customerId`
  routes; a Redaction Rules tab lists and creates rules against the real
  `GET`/`POST /redaction-rules`; a System tab shows live circuit-breaker
  health (`GET /circuit-breaker`, polled) plus an admin-key-gated
  fault-injection control for `POST /circuit-breaker/simulate-outage`,
  visually separated as a "danger zone" from normal operator actions.
- `public/js/` — split from a single flat `console.js` into ES modules
  (native `type="module"`, no bundler) once the new screens and dark-mode
  chrome pushed it past this project's own file-size convention.

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
  deferred hardening work — and that comparison is constant-time
  (`src/timingSafeCompare.ts`), not a plain `!==`, since it's the one real
  secret comparison anywhere in this codebase.

- Every store survives a restart when configured to — `AMBIT_DATA_DIR`
  turns on append-only JSONL persistence (`src/jsonlStore.ts`) for tokens,
  requests, policies, agent identities, redaction rules, and the audit log,
  live-verified by killing a running server outright and confirming the
  same token still enforces, with the same secret, after a real restart
  (see [ADR-014](adr/ADR-014-persistence-via-append-only-jsonl.md)). Off by
  default — every existing test's pure-in-memory behavior is unchanged.
  **What deliberately never touches disk:** ADR-013's transient token
  secret — an approved-but-unclaimed request's secret is unclaimable after
  a restart, on purpose, not by accident.

**What's still explicitly not real:** log rotation (the audit log file
grows unbounded), horizontal scaling (one file per store per process), and
corruption recovery beyond skip-and-warn on a bad line.
