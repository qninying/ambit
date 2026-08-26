# STORY-004 — Implement delegation narrowing for subagents

As a security officer, I want subagents to inherit a strict subset of their parent's scope, so that privilege escalation is prevented.

**Release:** r1 · Consent and Delegation (weeks 2–3)
**Owner:** Security Officer
**Blocked by:** STORY-001

## The requirement this satisfies

- **REQ-003** (Functional, must) — The system must enforce that a subagent can only inherit a strict subset of its parent's scope.
- **REQ-012** (Safety, must) — The system must ensure zero instances of a subagent obtaining a scope broader than its parent.

## How to build it

Implement delegation logic to enforce scope narrowing for subagents.

## Failure paths you must handle

- Subagent inherits full scope instead of subset.
- Delegation action is not logged.
- Excessive scope is incorrectly approved.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a subagent request, when it is processed, then it inherits a subset of the parent's scope.
- [ ] Given a subagent request, when it exceeds the parent's scope, then it is denied.
- [ ] Trust: Delegation actions are logged.

When every box above is ticked, stop and show the demo.
