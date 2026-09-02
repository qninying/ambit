# ADR-019: A Second Real Approver Identity, With Real Escalation

**Status:** Implemented. Closes the INPACT trust scorecard's Accountability dimension to Band 4.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-09-01
**Component:** `src/operatorDirectory.ts`, `src/tokenRequest.ts`, `src/auditLog.ts`, `src/server.ts`

---

## Context

Ambit was single-operator: one `ADMIN_USERNAME`, and any authenticated session could approve or deny *any* pending request — there was no assigned decider and nothing that happened if a request just sat there unresolved. The 2026-09-01 INPACT assessment named this as Accountability's one remaining gap.

Unlike Identity (ADR-017) and Non-repudiation (ADR-018), this one has no CoreOps dormant-mechanism precedent to wire up. CoreOps's own ADR-007 mostly connected credentials to an escalation mechanism (`hitlQueue.checkForTimeout()`) that already existed, fully tested, just never called. Ambit has no equivalent — the assignment/escalation mechanism itself had to be built from scratch here, not just wired.

## Decision

**Two parts, one ADR, matching CoreOps's own ADR-007 shape.**

### 1. A second real operator identity

New optional env vars `BACKUP_APPROVER_USERNAME` / `BACKUP_APPROVER_PASSWORD_HASH` / `BACKUP_APPROVER_TOTP_SECRET` — deliberately **not** fail-fast like the primary's three. Left unset, nothing changes: still single-operator, exactly as before this ADR.

`POST /auth/login`'s matching logic was extracted into `src/operatorDirectory.ts` (`OperatorIdentity`, `findAuthenticatedOperator()`) specifically so it gets real unit tests, following CoreOps's own "thin route, tested logic elsewhere" `userDirectory.ts` precedent. The matching loop preserves the exact short-circuit property the single-identity login already had (ADR-017): a wrong password for a given identity never reaches that identity's `totpVerifier.verify()`, so it can't burn or replay-block a currently-valid code — now transparently across one or two possible identities, with the same single generic `401` regardless of which (if either) partially matched.

**A real caching bug this ADR had to fix, not just work around:** ADR-017's `getTotpVerifier()` cached exactly one `TotpVerifier` in a single slot, keyed by secret. With two identities' secrets now potentially in play on the same server, a login attempt against one identity would evict the other's cached verifier — silently wiping its accumulated replay-protection state. Fixed by keying the cache on a `Map<string, TotpVerifier>` instead of a single slot, so both identities' verifiers coexist independently.

Each identity's three env vars are all-or-nothing (`resolveOperatorIdentity()`) — a partially configured backup (e.g. username set but not the hash) fails closed with a `503` naming the problem, rather than being silently skipped and leaving an operator believing a backup approver is live when it isn't.

### 2. A real per-request assignment + escalation mechanism, built new

- `PendingRequest` gains `assignedApprover?: string` — the primary approver's username at submission time (`requestToken()`'s new `primaryApprover` parameter, supplied by `server.ts` from `process.env.ADMIN_USERNAME`). Undefined only for the legacy case (a request created before any operator identity was configured), which preserves the old "any session can decide" behavior rather than making pre-existing requests suddenly undecidable.
- `approveRequest()`/`denyRequest()` now check the calling operator against `assignedApprover` via a shared `assertEligibleDecider()`. A mismatch throws a new `UnauthorizedDeciderError` (`403` at the HTTP boundary) — and the rejected attempt is itself recorded as its own audit fact, `request_decision_rejected` (a new, closed decision type, structurally required to carry a `reasonCode` — `"not_assigned_approver"` — the same structural guarantee `MissingReasonCodeError` already gives every denial), kept distinct from `request_denied` specifically because the *request itself* was not decided here, only the attempt was refused.
- `checkRequestTimeout()`: if a request is still pending, hasn't already escalated, and the configured decision window has elapsed, `assignedApprover` switches to the real backup identity's username and a new `request_escalated` audit entry is recorded. No scheduler exists in this system, so this is checked immediately before an approve/deny attempt runs — the same "one check right before the decision" placement CoreOps's own fix used for `checkForTimeout()`.

**Two deliberate divergences from CoreOps, stated rather than silently copied:**

- CoreOps's backup approver defaults to a hardcoded placeholder name (`"sre-oncall"`) even with no real credentials configured — meaning an escalation with no real backup set up leaves the request undecidable by anyone at all. `checkRequestTimeout()` is a no-op when no real backup identity is configured (`backupApprover` is `undefined`): the primary stays assigned indefinitely rather than the request being handed to a name nobody can log in as.
- CoreOps deliberately rejected an env-configurable decision window and did a genuine 15-minute real-time wait for its own live verification. `REQUEST_DECISION_WINDOW_MS` is env-overridable here (default 15 minutes in production) — a coding agent verifying this live can't usefully sit idle for 15 real minutes the way a human demo session can, and a short override for verification is a reasonable, stated reason to diverge, not a corner cut.

## Consequences

**What this closes:** Accountability's one remaining named gap. **Accountability moves from Band 3 to Band 4 (Hardened).** New aggregate: Identity 4 + Non-repudiation 4 + Provenance 3 + Accountability 4 + Control 4 + Transparency 3 = 22/6 = **3.67/4**, up from 3.5/4.

**What this explicitly does not cover:**
- A general N-approver model — this mirrors the exact two-role shape CoreOps's own ADR-007 chose (and confirmed directly with the user rather than assumed), not a general permissions system. A genuine third role would be the real trigger to revisit that.
- No `BACKUP_APPROVER_PASSWORD` (plaintext) equivalent, matching CoreOps's own reasoning — this identity exists for a real second human to log in, not for non-interactive automation, so a plaintext password has no consumer.
- Role-based access beyond the two roles the escalation model has.

## Verification

20 new tests. `operatorDirectory.test.ts` (9 — happy path for each identity, wrong password/code for each, an unconfigured backup never matches, an unknown username matches neither, and a cross-contamination case: a code valid for one identity's verifier never authenticates the other). `tokenRequest.test.ts`'s new "assignment & escalation (ADR-019)" block (8 — assignment at submission, the legacy undefined case, the assigned approver deciding normally, a non-assigned approver rejected on both approve and deny with the real audit entry, no escalation with no backup configured, no escalation before the window elapses, escalation firing and audited, the primary rejected and the backup succeeding after escalation, no double-escalation, no escalation of an already-decided request). `accountabilityWiring.test.ts` (3 — a real second HTTP login, the primary deciding within the window, and the full real-HTTP sequence: submit → wait past a real 150ms window → primary gets a real `403` → backup logs in and gets a real `200`). 319/319 total passing, `tsc --noEmit` clean.

Live-verified against a real running server, not just tests: real primary and backup identities (real password hashes, real TOTP secrets), `REQUEST_DECISION_WINDOW_MS=3000`. Registered an agent, submitted a request, waited past the real 3-second window, primary's approve attempt got a real `403` (`"demo-primary" is not the assigned approver for request "..." ("demo-backup" is)`), backup logged in for real and approved for real (`200`, a real token in the response). The Console's own Overview tab showed the complete, correctly-ordered real sequence: `request_token` (SUBMITTED) → `escalate_request` (REQUEST_ESCALATED, decision_window_expired) → `approve_request` (REQUEST_DECISION_REJECTED, not_assigned_approver, actor demo-primary) → `login` (ALLOWED, demo-backup) → `approve_request` (APPROVED, actor demo-backup).

## What would change this decision

- **A genuine third named role** (not just "more users," but the approval model itself growing a third distinct responsibility) would be the real trigger to move past the two-identity env-var pattern toward a general store.
- **Non-interactive automation needing the backup identity** would be the real trigger to add a plaintext backup password — no consumer exists for one today.
