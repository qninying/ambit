# STORY-011 — Support field-level redaction for customer data access

As a data privacy officer, I want field-level redaction for customer data access, so that sensitive information is protected.

**Release:** r4 · Final Enhancements (weeks 8–9)
**Owner:** Data Privacy Officer
**Blocked by:** STORY-010

## The requirement this satisfies

- **REQ-009** (Functional, must) — The system must support field-level redaction for customer data access.

## How to build it

Implement field-level redaction in the data access layer. Ensure all access and redaction actions are logged.

## Failure paths you must handle

- Unauthorized access attempt
- Redaction rule misconfiguration
- Data access layer failure

## Acceptance — your stop condition

Tick each box as it genuinely passes. This file is yours — the platform reads
the same criteria out of `.colaberry/progress.json`, which Claude Code keeps in
step (see the managed block in CLAUDE.md). Ticking something you have not
actually met only misleads you.

- [ ] Given a request for customer data, when the data is accessed, then sensitive fields are redacted.
- [ ] Given a request for customer data, when the request lacks proper authorization, then access is denied.
- [ ] Trust: Given any data access, when the data is accessed, then the access and redaction actions are logged in the Audit Log.

When every box above is ticked, stop and show the demo.
