# STORY-002 — Implement real-time revocation handling

As a security officer, I want revoked tokens to fail immediately, so that unauthorized access is prevented.

**Release:** r0 · Initial Skeleton (weeks 0–1)
**Owner:** Security Officer
**Blocked by:** nothing — you can start this now

## The requirement this satisfies

- **REQ-015** (Safety, must) — The system must ensure that a revoked token's next call fails within the same request cycle.

## How to build it

Ensure the Enforcement Gateway checks revocation status in real-time.

## Failure paths you must handle

- Revocation status check fails.
- Revoked token is not blocked.
- Revocation log entry fails.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a token, when it is revoked, then its next call fails immediately.
- [ ] Given a revoked token, when it is used, then the action is blocked.
- [ ] Trust: Revocation is logged with a reason code.

When every box above is ticked, stop and show the demo.
