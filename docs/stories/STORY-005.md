# STORY-005 — Integrate with mock endpoints and deny actions when token validity or scope cannot be confirmed

As a system administrator, I want the system to deny actions when token validity or scope cannot be confirmed, so that unauthorized actions are prevented.

**Release:** r2 · Integration and Anomaly Detection (weeks 4–5)
**Owner:** System Administrator
**Blocked by:** STORY-006

## The requirement this satisfies

- **REQ-006** (Safety, must) — The system must deny actions when token validity or scope cannot be confirmed.
- **REQ-007** (Constraint, must) — The system must integrate with mock endpoints for email, code hosting, payment, and CRM systems.

## How to build it

Ensure integration with mock endpoints includes checks for token validity and scope. Implement logging for all actions and outcomes in the Audit Log.

## Failure paths you must handle

- Token is expired
- Token scope is insufficient
- Endpoint is unreachable

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a valid token, when the token is used to access a mock endpoint, then the action is allowed.
- [ ] Given an invalid token, when the token is used to access a mock endpoint, then the action is denied.
- [ ] Trust: Given any token, when the token is used, then the action and its outcome are logged in the Audit Log.

When every box above is ticked, stop and show the demo.
