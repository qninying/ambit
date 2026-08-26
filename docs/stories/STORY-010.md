# STORY-010 — Provide detailed error messages for rejected tokens

As a developer, I want detailed error messages for rejected tokens, so that I can understand why a token was rejected.

**Release:** r4 · Final Enhancements (weeks 8–9)
**Owner:** Developer
**Blocked by:** STORY-008

## The requirement this satisfies

- **REQ-018** (Functional, must) — The system must provide error messages for rejected tokens indicating the reason (out of scope, expired, revoked).

## How to build it

Ensure error messages for rejected tokens are detailed and informative.

## Failure paths you must handle

- Error message is not detailed.
- Valid token incorrectly returns error.
- Error message action is not logged.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a rejected token, when it is used, then a detailed error message is returned.
- [ ] Given a valid token, when it is used, then no error message is returned.
- [ ] Trust: Error message actions are logged.

When every box above is ticked, stop and show the demo.
