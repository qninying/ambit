# STORY-007 — Develop policy management features

As a policy manager, I want to define token scopes and constraints, so that I can control access policies.

**Release:** r3 · Policy Management and SDK (weeks 6–7)
**Owner:** Policy Manager
**Blocked by:** STORY-006

## The requirement this satisfies

- **REQ-011** (Functional, must) — The system must allow policy definition for token scopes and constraints.
- **REQ-017** (Functional, must) — The system must provide a mechanism for human policy authorship and approval.

## How to build it

Implement policy management interface and logic for defining scopes and constraints.

## Failure paths you must handle

- Policy creation fails.
- Policy changes are not applied.
- Policy action is not logged.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a policy, when it is created, then it defines token scopes and constraints.
- [ ] Given a policy, when it is modified, then changes are applied.
- [ ] Trust: Policy actions are logged.

When every box above is ticked, stop and show the demo.
