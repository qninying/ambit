# ADR-004: Policy Enforcement Lives Inside `issueToken()`, Additive Not a Separate Gate

**Status:** Implemented — built, unit-tested, and live-verified (a policy edit changing what a subsequent approval allows, over real HTTP).
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-007)
**Component:** `src/policy.ts`, `src/token.ts` (`issueToken`), `src/tokenRequest.ts` (`approveRequest`)

---

## Context

REQ-011/REQ-017 ask for policy *definition* — a human-authored record of
allowed scope and TTL constraints. The literal acceptance criteria (create,
modify, log) could be satisfied by a passive record that nothing in the system
ever consults. That would make this the first inert feature in the build:
tested, logged, but not actually governing anything. Given the standing
direction to build real functionality rather than shortcuts that merely pass
tests, the decision was to make policy genuinely constrain issuance —
confirmed with the user before writing code, since it meaningfully expands the
story's scope and changes `issueToken()`'s signature.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| A policy that governs nothing isn't policy management | "Given a policy, when it is modified, then changes are applied" only means something if a modification changes real future behavior. |
| Zero regression to already-shipped stories | STORY-003 (`approveRequest`) and STORY-004 (`delegateToken`) were already built and tested against `issueToken()`'s existing signature. |
| A caller must not be able to forget to check | Optional-but-present-on-the-request is safer than optional-but-a-separate-call-site-must-remember-to-invoke-it. |

## Options considered

| | **A: Passive record, no enforcement** | **B: Separate `PolicyGate` service every caller must invoke** | **C: Optional `policyId` directly on `issueToken()`'s request (chosen)** |
|---|---|---|---|
| Actually governs anything | No | Yes, if remembered | Yes, unconditionally when present |
| Breaks existing callers | No, but inert | Only if they're not updated to call it | No — `policyId` is optional, absent means unchanged behavior |
| Can a caller forget | N/A | Yes — a new issuance call site that skips the gate silently bypasses policy | No — the check lives inside the one function that actually creates a token |

Option A was rejected as the "shortcut that passes tests without being real"
pattern this build has explicitly moved away from. Option B was rejected
because it reintroduces exactly the failure mode ADR-001 was written to close:
a mechanism whose correctness depends on every caller remembering to use it
correctly, rather than being structurally impossible to bypass.

## Decision

**`TokenRequest` gains an optional `policyId`. `issueToken(request, store,
policyStore?)` checks the request against that policy when a `policyId` is
present** — denying (throwing `PolicyViolationError`) if the requested scope
exceeds `allowedScope` or `ttlSeconds` exceeds `maxTtlSeconds`. Absent
`policyId`, behavior is byte-for-byte unchanged from before this story — no
regression to STORY-001/003/004. `approveRequest()` reads the `policyId` off
the pending request it's approving and threads it through, so a request
submitted with a policy attached is genuinely checked against it at the moment
a real token would be created, not at submission time (when the policy could
still change before approval).

A policy-blocked approval attempt is caught, logged with the real denial
reason, and leaves the request `pending` rather than consuming it — found as a
real gap during live testing (see ADR-008's sibling finding in the audit log
itself) and fixed in the same story.

## Consequences

**What this requires:** `PolicyStore` is looked up fresh on every `issueToken()`
call with a `policyId` present — this is what makes "modification takes
effect" provably true: re-issuing after editing a policy is checked against
the edited constraints, not a value cached at request-submission time.

**What this does not cover:** there is no default/mandatory policy — a request
with no `policyId` is checked only against the baseline Enforcement Gateway
rules (REQ-004/006), never against any policy at all. Making policy attachment
mandatory, or resolving multiple applicable policies by role/subject, was not
asked for and was not built.

## What would change this decision

A requirement for mandatory policy coverage (every issuance must be checked
against *some* policy) or for policy resolution by subject/role rather than
explicit `policyId` attachment would both be real scope changes to this
decision, not extensions of it.
