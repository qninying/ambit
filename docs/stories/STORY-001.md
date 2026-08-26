# STORY-001 — Issue and enforce a token with audit logging

As a developer, I want to issue a token and have it enforced, so that I can ensure secure access control for AI agents.

**Release:** r0 · Initial Skeleton (weeks 0–1)
**Owner:** Developer
**Blocked by:** nothing — you can start this now

## The requirement this satisfies

- **REQ-001** (Functional, must) — The system must issue short-lived, narrowly-scoped tokens for AI agents.
- **REQ-004** (Functional, must) — The system must validate token scope and revocation status in real-time at the Enforcement Gateway.
- **REQ-005** (Functional, must) — The system must log every allowed and blocked action to an immutable audit log.

## How to build it

Implement token issuance and enforcement logic. Ensure actions are logged to the Audit Log.

## Failure paths you must handle

- Token issuance fails due to invalid scope.
- Token enforcement fails due to revocation.
- Audit log entry fails to record action.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a token request, when it is approved, then the token is issued and enforced.
- [ ] Given a revoked token, when it is used, then the action is blocked.
- [ ] Trust: Every action is logged in the Audit Log.

When every box above is ticked, stop and show the demo.
