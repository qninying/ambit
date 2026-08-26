// REQ-011/REQ-017: human-authored policies defining token scope/constraints.
// Not a passive record — issueToken() (token.ts) can check a request against
// a policy by id when one is given, so modifying a policy genuinely changes
// what future issuance under it allows, not just what's stored.

import type { AuditLog } from "./auditLog.js";

export interface Policy {
  id: string;
  name: string;
  allowedScope: string[];
  maxTtlSeconds: number;
  authoredBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyInput {
  name: string;
  allowedScope: string[];
  maxTtlSeconds: number;
}

export class InvalidPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPolicyError";
  }
}

export class UnknownPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnknownPolicyError";
  }
}

export class PolicyStore {
  #policies = new Map<string, Policy>();

  save(policy: Policy): void {
    this.#policies.set(policy.id, policy);
  }

  get(id: string): Policy | undefined {
    return this.#policies.get(id);
  }

  list(): Policy[] {
    return [...this.#policies.values()];
  }
}

function validate(input: PolicyInput): void {
  if (!input.name || input.name.trim().length === 0) {
    throw new InvalidPolicyError("name is required");
  }
  if (input.allowedScope.length === 0) {
    throw new InvalidPolicyError("allowedScope must include at least one permission");
  }
  if (input.maxTtlSeconds <= 0) {
    throw new InvalidPolicyError("maxTtlSeconds must be positive");
  }
}

// Acceptance: "Given a policy, when it is created, then it defines token
// scopes and constraints."
export function createPolicy(
  input: PolicyInput,
  authoredBy: string,
  store: PolicyStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): Policy {
  validate(input);
  const policy: Policy = {
    id: crypto.randomUUID(),
    name: input.name,
    allowedScope: input.allowedScope,
    maxTtlSeconds: input.maxTtlSeconds,
    authoredBy,
    createdAt: now,
    updatedAt: now,
  };
  store.save(policy);
  auditLog.record({ policyId: policy.id, subject: authoredBy, action: "create_policy", decision: "policy_created" }, now);
  return policy;
}

// Acceptance: "Given a policy, when it is modified, then changes are
// applied." Proof of "applied" lives in token.ts's tests — the next
// issuance checked against this policy sees the new constraints, not stale
// ones, because issueToken() looks the policy up fresh by id every time.
export function modifyPolicy(
  policyId: string,
  changes: Partial<PolicyInput>,
  authoredBy: string,
  store: PolicyStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): Policy {
  const existing = store.get(policyId);
  if (!existing) {
    throw new UnknownPolicyError(`cannot modify policy "${policyId}" — no such policy exists`);
  }

  const updated: Policy = {
    ...existing,
    name: changes.name ?? existing.name,
    allowedScope: changes.allowedScope ?? existing.allowedScope,
    maxTtlSeconds: changes.maxTtlSeconds ?? existing.maxTtlSeconds,
    updatedAt: now,
  };
  validate(updated);
  store.save(updated);
  auditLog.record({ policyId, subject: authoredBy, action: "modify_policy", decision: "policy_modified" }, now);
  return updated;
}
