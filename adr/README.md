# Architecture Decision Records

Real decisions made while building Ambit, recorded as they happened — not
written retroactively to look good. Each one names the alternatives that were
actually considered and why they were rejected, not just the choice made.

| ADR | Decision | Story |
|---|---|---|
| [001](ADR-001-fresh-lookup-stores-as-source-of-truth.md) | Fresh-lookup stores as the single source of truth — rejected pass-by-value, which would have made "revoked token blocked" pass in a test without being real | STORY-002 |
| [002](ADR-002-delegation-invariants-enforced-in-primitives.md) | Delegation invariants (expiry cap, cascading revocation) enforced inside the primitives, not left as documented gaps | STORY-004 |
| [003](ADR-003-runtime-configurable-thresholds.md) | Runtime-configurable thresholds instead of hardcoded constants — a wrong guess is a config change, not a code change | STORY-005/006 |
| [004](ADR-004-policy-enforcement-inside-issue-token.md) | Policy enforcement lives inside `issueToken()` itself, additive — not a passive record, not a gate a caller could forget to invoke | STORY-007 |
| [005](ADR-005-audit-log-separates-decision-from-outcome.md) | Audit log separates the gateway's decision from the downstream outcome as two entries, not one overloaded field | STORY-005 |
| [006](ADR-006-in-memory-persistence-now.md) | In-memory persistence now, deliberately, with a same-interface graduation path — not an oversight | Running theme |
| [007](ADR-007-single-tabbed-console-enterprise-density.md) | Single tabbed console, enterprise-density design — rejected a consumer-app/map-centric framing as a domain mismatch | STORY-007 |
| [008](ADR-008-hash-chained-tamper-evident-audit-log.md) | Hash-chained, tamper-evident audit log — "immutable" made checkable, not just claimed in a comment | Post-STORY-007 |
| [009](ADR-009-trust-boundary-hardening-deferred-to-post-platform-phase.md) | No caller authentication, no verified approver identity, no token possession proof — named explicitly, bundled with real persistence, deferred to a dedicated phase after STORY-012 rather than left implicit | Post-STORY-008 |
| [010](ADR-010-policy-selection-moved-to-approval-time.md) | Policy selection moved to approval time — a requester could previously cite their own policy on their own request, turning "policy attached" into a self-issued rubber stamp | Post-STORY-012 |
| [011](ADR-011-real-operator-authentication-first-slice.md) | Real operator authentication (hand-rolled signed sessions, no new dependency) — first slice of ADR-009's hardening phase, closing "verified approver identity" for approve/deny specifically; every other route is still open | Post-STORY-012 |
