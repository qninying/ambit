# ADR-003: Runtime-Configurable Thresholds Instead of Hardcoded Constants

**Status:** Implemented — built, unit-tested, and live-verified via an env-var override actually changing behavior.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (STORY-005, STORY-006)
**Component:** `src/anomalyDetector.ts`, `src/mockEndpointAccess.ts`, `src/server.ts`

---

## Context

STORY-006 needed two anomaly-detection thresholds (scope breadth, request
velocity) and STORY-005 needed timeout/retry parameters for calling a mock
endpoint. Neither has a value specified anywhere in the requirements — they're
judgment calls. The first implementation hardcoded them as module-level
constants.

After STORY-006 shipped, the user asked for the reported confidence score to
move from 85% to 90% without anything else changing. The honest answer was to
decline relabeling the number and instead close the actual gap the low score
was naming: the thresholds were unconfirmed and hardcoded, meaning a wrong
guess would require a code change to fix. That gap was closed by making the
thresholds configurable. The same "no hardcoded magic" standard was then
applied proactively to STORY-005's timeout/retry numbers one story later,
without being asked again.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| These are judgment calls, not facts | Nothing in the requirements docs says "3 scope items" or "3 requests per 60 seconds" — those are reasonable defaults, not derived values. |
| A wrong guess should be cheap to fix | The difference between "config change" and "code change" is the difference between an ops adjustment and a redeploy. |
| No new dependency, no premature scope | A full admin-editable settings API/UI would be real scope creep for a walking skeleton — the actual problem is narrower than that. |

## Options considered

| | **A: Hardcoded constants (original)** | **B: Constructor-injectable config + env var overrides (chosen)** | **C: Full runtime settings API/UI** |
|---|---|---|---|
| Fixes the actual gap named by the low confidence score | No | Yes | Yes, but far more than the gap requires |
| New scope/dependency | None | None (plain object config, `process.env` reads) | New endpoints, likely a persistence question for settings themselves |
| Testable | Constants can't be tested against alternate values without editing source | Directly — a test can construct with any config and assert the different behavior | Same as B, plus more surface to test |

Option C was rejected as solving a problem one level bigger than the one that
was actually named — the gap was "a wrong guess costs a code change," not "no
one can ever adjust these without deploying," and the latter doesn't require a
full settings service.

## Decision

**`AnomalyDetectorConfig` and `MockEndpointAccessConfig` are both
constructor-injectable, with a single centralized default object each**
(`DEFAULT_ANOMALY_CONFIG`, `DEFAULT_MOCK_ENDPOINT_ACCESS_CONFIG`). Merging uses
`??`, not object spread, so an explicit `undefined` (e.g. an unset env var)
correctly falls back to the default rather than silently becoming `undefined`
itself. `server.ts` reads `ANOMALY_MAX_SCOPE_BREADTH` /
`ANOMALY_VELOCITY_WINDOW_MS` / `ANOMALY_MAX_REQUESTS_PER_WINDOW` and
`ACCESS_TIMEOUT_MS` / `ACCESS_MAX_ATTEMPTS` / `ACCESS_RETRY_DELAY_MS` to
override at process start.

## Consequences

**What this requires:** every threshold-consuming function takes an optional
config parameter rather than reading a module constant directly — a small but
real API surface change from the first hardcoded version.

**Verified, not just declared:** started the server with
`ANOMALY_MAX_SCOPE_BREADTH=1` and confirmed a 2-item scope request was flagged
that would not have been under the default — proving the override actually
changes runtime behavior, not just that the constructor accepts a parameter.

## What would change this decision

If thresholds ever needed to vary *per subject or per policy* rather than
process-wide, that would belong on the `Policy` model itself (see ADR-004),
not as a broader set of environment variables.
