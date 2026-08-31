import { describe, expect, it, vi } from "vitest";
import { AuditLog } from "./auditLog.js";
import { issueToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { CustomerDataRegistry } from "./customerData.js";
import { RedactionRuleStore, createRedactionRule } from "./redaction.js";
import { accessCustomerData } from "./customerDataAccess.js";

function setup() {
  const tokenStore = new TokenStore();
  const auditLog = new AuditLog();
  const customerRegistry = new CustomerDataRegistry();
  const redactionRuleStore = new RedactionRuleStore();
  const rule = createRedactionRule(
    { name: "Standard PII", sensitiveFields: { ssn: "customer:read:ssn", email: "customer:read:email" } },
    "privacy-officer-1",
    redactionRuleStore,
    auditLog,
  );
  return { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule };
}

describe("accessCustomerData", () => {
  // Acceptance: "Given a request for customer data, when the data is
  // accessed, then sensitive fields are redacted."
  it("allows access and redacts fields the token's scope doesn't grant", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);

    const result = await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    if (!result.allowed) throw new Error("expected access to be allowed");
    expect(result.data.ssn).toBe("[REDACTED]");
    expect(result.data.email).toBe("[REDACTED]");
    expect(result.data.name).toBeTruthy(); // not in the rule — never redacted
    expect(result.redactedFields.sort()).toEqual(["email", "ssn"]);
  });

  it("un-redacts exactly the fields the token has elevated scope for", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken(
      { subject: "agent-42", scope: ["customer:read", "customer:read:ssn"], ttlSeconds: 300 },
      tokenStore,
    );

    const result = await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    if (!result.allowed) throw new Error("expected access to be allowed");
    expect(result.data.ssn).not.toBe("[REDACTED]");
    expect(result.data.email).toBe("[REDACTED]");
  });

  // Acceptance: "Given a request for customer data, when the request lacks
  // proper authorization, then access is denied." Reuses enforceToken as-is
  // — nothing about REQ-004/006/018's guardrails is reimplemented here.
  it("denies access when the token lacks the customer:read scope, and never reaches the customer registry", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    const spy = vi.spyOn(customerRegistry, "get");

    const result = await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    expect(result.allowed).toBe(false);
    if (result.allowed) throw new Error("unreachable");
    expect(result.reasonCode).toBe("out_of_scope");
    expect("data" in result).toBe(false); // the denial response must never carry customer data
    expect(spy).not.toHaveBeenCalled();
  });

  it("denies access for an unknown token id", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const result = await accessCustomerData("not-a-real-token", "irrelevant-secret", "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    expect(result.allowed).toBe(false);
    if (result.allowed) throw new Error("unreachable");
    expect(result.reasonCode).toBe("unknown_token");
  });

  // ADR-013: knowing a token's id is not enough — the coarse enforceToken
  // gate this route delegates to now requires proof of possession first.
  it("denies access with invalid_credential when the wrong secret is provided, and never reaches the customer registry", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token } = await issueToken({ subject: "agent-42", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);
    const spy = vi.spyOn(customerRegistry, "get");

    const result = await accessCustomerData(token.id, "wrong-secret", "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    expect(result.allowed).toBe(false);
    if (result.allowed) throw new Error("unreachable");
    expect(result.reasonCode).toBe("invalid_credential");
    expect(spy).not.toHaveBeenCalled();
  });

  it("denies access for an unknown customer id, even with a fully valid, authorized token", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);

    const result = await accessCustomerData(token.id, secret, "not-a-real-customer", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    expect(result.allowed).toBe(false);
    if (result.allowed) throw new Error("unreachable");
    expect(result.reasonCode).toBe("unknown_customer");
  });

  // Failure path: "Redaction rule misconfiguration" — the security-critical
  // case. A rule that can't be resolved must deny the whole request, never
  // fall back to returning the record unredacted.
  it("fails closed — denies access — when the redaction rule id cannot be resolved, rather than returning unredacted data", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);

    const result = await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, "not-a-real-rule-id");

    expect(result.allowed).toBe(false);
    if (result.allowed) throw new Error("unreachable");
    expect(result.reasonCode).toBe("redaction_rule_unavailable");
    expect("data" in result).toBe(false);
  });

  // Trust: "the access and redaction actions are logged" — two entries,
  // deliberately (ADR-005's "decision separate from outcome" pattern).
  it("logs both the access decision and the redaction outcome as two separate entries", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);

    await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    const entries = auditLog.entries().filter((e) => e.tokenId === token.id);
    expect(entries).toContainEqual(expect.objectContaining({ decision: "allowed", action: "customer:read" }));
    expect(entries).toContainEqual(
      expect.objectContaining({ decision: "data_accessed", redactedFields: expect.arrayContaining(["ssn", "email"]) }),
    );
  });

  it("logs a denial (and nothing else) when access is refused, with no data_accessed entry", async () => {
    const { tokenStore, auditLog, customerRegistry, redactionRuleStore, rule } = setup();
    const { token, secret } = await issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);

    await accessCustomerData(token.id, secret, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id);

    const entries = auditLog.entries().filter((e) => e.tokenId === token.id);
    expect(entries.some((e) => e.decision === "data_accessed")).toBe(false);
    expect(entries).toContainEqual(expect.objectContaining({ decision: "denied", reasonCode: "out_of_scope" }));
  });
});
