import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { InvalidRedactionRuleError, RedactionRuleStore, REDACTION_MASK, applyRedaction, createRedactionRule } from "./redaction.js";
import type { CustomerRecord } from "./customerData.js";

function setup() {
  return { store: new RedactionRuleStore(), auditLog: new AuditLog() };
}

const SAMPLE_CUSTOMER: CustomerRecord = {
  id: "cust-001",
  name: "Jordan Ellis",
  email: "jordan.ellis@example.com",
  phone: "555-0101",
  ssn: "123-45-6789",
  address: "12 Birch Street, Springfield",
};

describe("createRedactionRule", () => {
  it("creates a rule with the given sensitive fields and logs it", () => {
    const { store, auditLog } = setup();
    const rule = createRedactionRule({ name: "PII", sensitiveFields: { ssn: "customer:read:ssn" } }, "privacy-officer-1", store, auditLog);

    expect(rule.sensitiveFields).toEqual({ ssn: "customer:read:ssn" });
    expect(store.get(rule.id)).toEqual(rule);
    expect(auditLog.entries()).toContainEqual(expect.objectContaining({ decision: "redaction_rule_created", subject: "privacy-officer-1" }));
  });

  // Failure path: "Redaction rule misconfiguration" — a rule that protects
  // nothing is rejected at creation, not discovered later as a leak.
  it("refuses to create a rule with no sensitive fields", () => {
    const { store, auditLog } = setup();
    expect(() => createRedactionRule({ name: "Empty", sensitiveFields: {} }, "privacy-officer-1", store, auditLog)).toThrow(
      InvalidRedactionRuleError,
    );
  });

  // Failure path: a field mapped to an empty scope could never be
  // un-redacted by anyone — almost certainly a mistake, not intent.
  it("refuses to create a rule where a field's required scope is empty", () => {
    const { store, auditLog } = setup();
    expect(() => createRedactionRule({ name: "Bad", sensitiveFields: { ssn: "" } }, "privacy-officer-1", store, auditLog)).toThrow(
      InvalidRedactionRuleError,
    );
  });

  it("refuses to create a rule with no name", () => {
    const { store, auditLog } = setup();
    expect(() => createRedactionRule({ name: "", sensitiveFields: { ssn: "customer:read:ssn" } }, "privacy-officer-1", store, auditLog)).toThrow(
      InvalidRedactionRuleError,
    );
  });
});

describe("applyRedaction", () => {
  const rule = {
    id: "rule-1",
    name: "Standard PII",
    sensitiveFields: { ssn: "customer:read:ssn", email: "customer:read:email" },
    authoredBy: "privacy-officer-1",
    createdAt: new Date(),
  };

  // Acceptance: "Given a request for customer data, when the data is
  // accessed, then sensitive fields are redacted."
  it("redacts sensitive fields the token's scope does not grant", () => {
    const result = applyRedaction(SAMPLE_CUSTOMER, rule, ["customer:read"]);

    expect(result.data.ssn).toBe(REDACTION_MASK);
    expect(result.data.email).toBe(REDACTION_MASK);
    expect(result.redactedFields.sort()).toEqual(["email", "ssn"]);
  });

  it("leaves fields not named in the rule untouched, regardless of scope", () => {
    const result = applyRedaction(SAMPLE_CUSTOMER, rule, ["customer:read"]);

    expect(result.data.name).toBe("Jordan Ellis");
    expect(result.data.address).toBe(SAMPLE_CUSTOMER.address);
  });

  it("un-redacts exactly the fields whose required scope is present — field-level, not all-or-nothing", () => {
    const result = applyRedaction(SAMPLE_CUSTOMER, rule, ["customer:read", "customer:read:ssn"]);

    expect(result.data.ssn).toBe(SAMPLE_CUSTOMER.ssn); // scope present — visible
    expect(result.data.email).toBe(REDACTION_MASK); // scope still missing — redacted
    expect(result.redactedFields).toEqual(["email"]);
  });

  it("redacts nothing when the token has every required scope", () => {
    const result = applyRedaction(SAMPLE_CUSTOMER, rule, ["customer:read", "customer:read:ssn", "customer:read:email"]);

    expect(result.data).toEqual(SAMPLE_CUSTOMER);
    expect(result.redactedFields).toEqual([]);
  });

  it("does not mutate the original record", () => {
    const original = { ...SAMPLE_CUSTOMER };
    applyRedaction(SAMPLE_CUSTOMER, rule, []);

    expect(SAMPLE_CUSTOMER).toEqual(original);
  });
});
