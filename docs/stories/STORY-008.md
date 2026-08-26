# STORY-008 — Provide a client SDK for token requests

As a developer, I want a client SDK to request and present tokens, so that I can easily integrate with Ambit.

**Release:** r3 · Policy Management and SDK (weeks 6–7)
**Owner:** Developer
**Blocked by:** STORY-006

## The requirement this satisfies

- **REQ-014** (Functional, must) — The system must provide a client SDK for developers to request and present tokens.

## How to build it

Develop a client SDK for token requests and ensure it handles errors appropriately.

## Failure paths you must handle

- SDK fails to request token.
- Invalid token request does not return error.
- SDK usage is not logged.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a developer, when they use the SDK, then they can request a token.
- [ ] Given a token request, when it is invalid, then an error is returned.
- [ ] Trust: SDK usage is logged.

When every box above is ticked, stop and show the demo.
