import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { InvalidPolicyError, PolicyStore, UnknownPolicyError, createPolicy, modifyPolicy } from "./policy.js";

function setup() {
  return { store: new PolicyStore(), auditLog: new AuditLog() };
}

describe("createPolicy", () => {
  // Acceptance: "Given a policy, when it is created, then it defines token
  // scopes and constraints."
  it("creates a policy with the given scope and TTL constraints", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send", "crm:read"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    expect(policy.allowedScope).toEqual(["email:send", "crm:read"]);
    expect(policy.maxTtlSeconds).toBe(3600);
    expect(policy.authoredBy).toBe("policy-manager-1");
    expect(store.get(policy.id)).toEqual(policy);
  });

  // Failure path: "Policy creation fails."
  it("refuses to create a policy with no name", () => {
    const { store, auditLog } = setup();
    expect(() =>
      createPolicy({ name: "", allowedScope: ["email:send"], maxTtlSeconds: 3600 }, "policy-manager-1", store, auditLog),
    ).toThrow(InvalidPolicyError);
  });

  it("refuses to create a policy with an empty allowedScope", () => {
    const { store, auditLog } = setup();
    expect(() =>
      createPolicy({ name: "Empty policy", allowedScope: [], maxTtlSeconds: 3600 }, "policy-manager-1", store, auditLog),
    ).toThrow(InvalidPolicyError);
  });

  it("refuses to create a policy with a non-positive maxTtlSeconds", () => {
    const { store, auditLog } = setup();
    expect(() =>
      createPolicy({ name: "Bad TTL", allowedScope: ["email:send"], maxTtlSeconds: 0 }, "policy-manager-1", store, auditLog),
    ).toThrow(InvalidPolicyError);
  });

  // Trust: "Policy actions are logged."
  it("logs policy creation with the authoring policy manager", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    expect(auditLog.entries()).toEqual([
      expect.objectContaining({ policyId: policy.id, subject: "policy-manager-1", decision: "policy_created" }),
    ]);
  });
});

describe("modifyPolicy", () => {
  it("updates the stored policy's constraints", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    const updated = modifyPolicy(policy.id, { allowedScope: ["email:send", "crm:read"], maxTtlSeconds: 1800 }, "policy-manager-1", store, auditLog);

    expect(updated.allowedScope).toEqual(["email:send", "crm:read"]);
    expect(updated.maxTtlSeconds).toBe(1800);
    expect(store.get(policy.id)).toEqual(updated);
  });

  it("leaves fields not included in the change untouched", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    const updated = modifyPolicy(policy.id, { maxTtlSeconds: 1800 }, "policy-manager-1", store, auditLog);

    expect(updated.allowedScope).toEqual(["email:send"]);
    expect(updated.name).toBe("Standard agent access");
  });

  it("refuses to modify an unknown policy id", () => {
    const { store, auditLog } = setup();
    expect(() => modifyPolicy("not-a-real-id", { maxTtlSeconds: 60 }, "policy-manager-1", store, auditLog)).toThrow(
      UnknownPolicyError,
    );
  });

  it("refuses a modification that would leave the policy invalid", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    expect(() => modifyPolicy(policy.id, { allowedScope: [] }, "policy-manager-1", store, auditLog)).toThrow(InvalidPolicyError);
  });

  it("logs policy modification separately from creation", () => {
    const { store, auditLog } = setup();
    const policy = createPolicy(
      { name: "Standard agent access", allowedScope: ["email:send"], maxTtlSeconds: 3600 },
      "policy-manager-1",
      store,
      auditLog,
    );

    modifyPolicy(policy.id, { maxTtlSeconds: 1800 }, "policy-manager-1", store, auditLog);

    const entries = auditLog.entries();
    expect(entries).toHaveLength(2);
    expect(entries[1]).toMatchObject({ policyId: policy.id, decision: "policy_modified" });
  });
});
