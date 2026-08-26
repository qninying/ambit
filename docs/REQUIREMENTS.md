# Ambit — Requirements

An OAuth-style identity and access management system for autonomous AI agents, providing short-lived, narrowly-scoped tokens with human approval and real-time enforcement.

This is the source of truth for what you are building. Your Claude Code prompts
point here. If you sharpen a requirement, edit it — your version is the real one.

| Kind | Meaning |
|---|---|
| Functional | something the system does |
| Safety | a guardrail, with a check that enforces it |
| Reliability | how it behaves when something fails |
| Constraint | a technology or vendor you must use — context, not a task |

## Audit Logging

### REQ-005 — Functional · must

The system must log every allowed and blocked action to an immutable audit log.

Fulfilled by: STORY-001

### REQ-010 — Functional · must

The system must provide distinct reason codes for denied actions in the Audit Log.

Fulfilled by: STORY-012

## Consent Management

### REQ-002 — Functional · must

The system must allow human approval for every token request via a plain-language consent screen.

Fulfilled by: STORY-003

### REQ-013 — Functional · must

The system must provide a Consent UI for approvers to review and approve token requests.

Fulfilled by: STORY-003

## Data Management

### REQ-009 — Functional · must

The system must support field-level redaction for customer data access.

Fulfilled by: STORY-011

## Delegation Management

### REQ-003 — Functional · must

The system must enforce that a subagent can only inherit a strict subset of its parent's scope.

Fulfilled by: STORY-004

### REQ-012 — Safety · must

The system must ensure zero instances of a subagent obtaining a scope broader than its parent.

Fulfilled by: STORY-004

## Developer Experience

### REQ-014 — Functional · must

The system must provide a client SDK for developers to request and present tokens.

Fulfilled by: STORY-008

### REQ-018 — Functional · must

The system must provide error messages for rejected tokens indicating the reason (out of scope, expired, revoked).

Fulfilled by: STORY-010

## Enforcement

### REQ-004 — Functional · must

The system must validate token scope and revocation status in real-time at the Enforcement Gateway.

Fulfilled by: STORY-001

### REQ-006 — Safety · must

The system must deny actions when token validity or scope cannot be confirmed.

Fulfilled by: STORY-005

### REQ-008 — Safety · must

The system must provide a fail-closed circuit-breaker state when the Policy & Token Store is unreachable.

Fulfilled by: STORY-009

### REQ-015 — Safety · must

The system must ensure that a revoked token's next call fails within the same request cycle.

Fulfilled by: STORY-002

## Integration

### REQ-007 — Constraint

The system must integrate with mock endpoints for email, code hosting, payment, and CRM systems.

Fulfilled by: STORY-005

## Policy Management

### REQ-011 — Functional · must

The system must allow policy definition for token scopes and constraints.

Fulfilled by: STORY-007

### REQ-017 — Functional · must

The system must provide a mechanism for human policy authorship and approval.

Fulfilled by: STORY-007

## Security

### REQ-016 — Functional · must

The system must support anomaly detection for token requests.

Fulfilled by: STORY-006

## Token Issuance

### REQ-001 — Functional · must

The system must issue short-lived, narrowly-scoped tokens for AI agents.

Fulfilled by: STORY-001
