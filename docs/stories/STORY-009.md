# STORY-009 — Implement fail-closed circuit-breaker for Policy & Token Store

As a security officer, I want a fail-closed circuit-breaker for the Policy & Token Store, so that I can ensure system security during outages.

**Release:** r4 · Final Enhancements (weeks 8–9)
**Owner:** Security Officer
**Blocked by:** STORY-008

## The requirement this satisfies

- **REQ-008** (Safety, must) — The system must provide a fail-closed circuit-breaker state when the Policy & Token Store is unreachable.

## How to build it

Implement fail-closed logic for the Policy & Token Store and integrate with the alerting system.

## Failure paths you must handle

- Circuit-breaker fails to activate.
- Request is incorrectly processed during outage.
- Circuit-breaker action is not logged.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given the Policy & Token Store is unreachable, when a request is made, then it is denied.
- [ ] Given the Store is reachable, when a request is made, then it is processed.
- [ ] Trust: Circuit-breaker actions are logged.

When every box above is ticked, stop and show the demo.
