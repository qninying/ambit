# STORY-006 — Implement anomaly detection for token requests

As a security officer, I want to detect anomalies in token requests, so that I can respond to potential security threats.

**Release:** r2 · Integration and Anomaly Detection (weeks 4–5)
**Owner:** Security Officer
**Blocked by:** STORY-004

## The requirement this satisfies

- **REQ-016** (Functional, must) — The system must support anomaly detection for token requests.

## How to build it

Develop anomaly detection logic for token requests and integrate with the alerting system.

## Failure paths you must handle

- Anomaly is not detected.
- False positive alert is triggered.
- Anomaly detection action is not logged.

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a token request, when it is anomalous, then an alert is triggered.
- [ ] Given a normal request, when it is processed, then no alert is triggered.
- [ ] Trust: Anomaly detection actions are logged.

When every box above is ticked, stop and show the demo.
