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
