# STORY-003 — Implement Consent UI for token approval

As an approver, I want to approve token requests via a Consent UI, so that I can control access securely.

**Release:** r1 · Consent and Delegation (weeks 2–3)
**Owner:** Approver
**Blocked by:** STORY-001

## The requirement this satisfies

- **REQ-002** (Functional, must) — The system must allow human approval for every token request via a plain-language consent screen.
- **REQ-013** (Functional, must) — The system must provide a Consent UI for approvers to review and approve token requests.

## How to build it

Develop the Consent UI for token approval and integrate with the token issuance process.

## Failure paths you must handle

- Consent UI fails to load.
- Approval action is not logged.
- Denied request is incorrectly issued.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a token request, when it is displayed, then the approver can approve or deny it.
- [ ] Given a denied request, when it is submitted, then the token is not issued.
- [ ] Trust: Approval actions are logged.

When every box above is ticked, stop and show the demo.
