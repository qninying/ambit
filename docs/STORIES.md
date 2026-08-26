# Ambit — Stories

12 stories across 5 releases, walking-skeleton first:
the earliest release proves the thinnest end-to-end path including the trust
spine, and later releases stack features on top of something already working.

## Before the releases — start here

- **[STORY-000](stories/STORY-000.md)** — Build your Command Center

The first thing you build, on day one, before any part of the system itself. It is
the page you keep open for the rest of the programme and demo from. It belongs to no
release and fulfils none of your requirements, because it is the window onto your
system rather than a part of it.

## r0 · Initial Skeleton — weeks 0–1

**Goal:** Establish the core token issuance and enforcement mechanism with audit logging.
**Done when you can show:** Show a token being issued, approved, enforced, and logged with real-time revocation handling.

- **[STORY-001](stories/STORY-001.md)** — Issue and enforce a token with audit logging
- **[STORY-002](stories/STORY-002.md)** — Implement real-time revocation handling

## r1 · Consent and Delegation — weeks 2–3

**Goal:** Implement consent management and delegation narrowing features.
**Done when you can show:** Demonstrate human approval via Consent UI and subagent scope narrowing in action.

- **[STORY-003](stories/STORY-003.md)** — Implement Consent UI for token approval _(waits on STORY-001)_
- **[STORY-004](stories/STORY-004.md)** — Implement delegation narrowing for subagents _(waits on STORY-001)_

## r2 · Integration and Anomaly Detection — weeks 4–5

**Goal:** Integrate with mock endpoints and implement anomaly detection.
**Done when you can show:** Show integration with mock systems and anomaly detection triggering alerts.

- **[STORY-005](stories/STORY-005.md)** — Integrate with mock endpoints and deny actions when token validity or scope cannot be confirmed _(waits on STORY-006)_
- **[STORY-006](stories/STORY-006.md)** — Implement anomaly detection for token requests _(waits on STORY-004)_

## r3 · Policy Management and SDK — weeks 6–7

**Goal:** Develop policy management features and provide a client SDK.
**Done when you can show:** Show policy creation and a developer using the SDK to request tokens.

- **[STORY-007](stories/STORY-007.md)** — Develop policy management features _(waits on STORY-006)_
- **[STORY-008](stories/STORY-008.md)** — Provide a client SDK for token requests _(waits on STORY-006)_

## r4 · Final Enhancements — weeks 8–9

**Goal:** Implement final safety and usability enhancements.
**Done when you can show:** Demonstrate fail-closed circuit-breaker and detailed error messages for developers.

- **[STORY-009](stories/STORY-009.md)** — Implement fail-closed circuit-breaker for Policy & Token Store _(waits on STORY-008)_
- **[STORY-010](stories/STORY-010.md)** — Provide detailed error messages for rejected tokens _(waits on STORY-008)_
- **[STORY-011](stories/STORY-011.md)** — Support field-level redaction for customer data access _(waits on STORY-010)_
- **[STORY-012](stories/STORY-012.md)** — Provide distinct reason codes for denied actions in the Audit Log _(waits on STORY-011)_
