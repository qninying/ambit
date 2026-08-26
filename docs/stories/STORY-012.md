# STORY-012 — Provide distinct reason codes for denied actions in the Audit Log

As a compliance officer, I want distinct reason codes for denied actions in the Audit Log, so that I can understand why actions were denied.

**Release:** r4 · Final Enhancements (weeks 8–9)
**Owner:** Compliance Officer
**Blocked by:** STORY-011

## The requirement this satisfies

- **REQ-010** (Functional, must) — The system must provide distinct reason codes for denied actions in the Audit Log.

## How to build it

Update the Audit Log schema to include reason codes for denied actions. Implement logic to assign reason codes based on denial reasons.

## Failure paths you must handle

- Reason code not assigned
- Incorrect reason code assigned
- Audit Log update failure

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a denied action, when the action is logged, then a distinct reason code is recorded.
- [ ] Given a denied action due to token expiration, when the action is logged, then the reason code indicates token expiration.
- [ ] Trust: Given any denied action, when the action is logged, then the reason code is included in the Audit Log.

When every box above is ticked, stop and show the demo.
