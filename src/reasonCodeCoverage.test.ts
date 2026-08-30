// REQ-010, holistic: not "each function individually returns a reasonCode
// when its own tests check it," but "across the real system, a compliance
// officer reviewing the Audit Log sees a distinct, correct reason for
// every denied action." This exercises several unrelated subsystems
// together and checks the resulting audit trail as a whole, the way an
// actual reviewer would.

import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { enforceToken, issueToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { delegateToken } from "./delegation.js";
import { RequestStore } from "./requestStore.js";
import { AnomalyDetector } from "./anomalyDetector.js";
import { denyRequest, requestToken } from "./tokenRequest.js";
import { CustomerDataRegistry } from "./customerData.js";
import { RedactionRuleStore, createRedactionRule } from "./redaction.js";
import { accessCustomerData } from "./customerDataAccess.js";

describe("REQ-010: distinct reason codes across the real system", () => {
  it("assigns a distinct, correct reasonCode to denials from unrelated subsystems, and every one is present in the Audit Log", () => {
    const auditLog = new AuditLog();
    const tokenStore = new TokenStore();
    const requestStore = new RequestStore();
    const anomalyDetector = new AnomalyDetector();
    const customerRegistry = new CustomerDataRegistry();
    const redactionRuleStore = new RedactionRuleStore();
    const rule = createRedactionRule({ name: "PII", sensitiveFields: { ssn: "customer:read:ssn" } }, "privacy-officer-1", redactionRuleStore, auditLog);

    // Acceptance: "Given a denied action due to token expiration, when the
    // action is logged, then the reason code indicates token expiration."
    const expiredToken = issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    enforceToken(expiredToken.id, "email:send", tokenStore, auditLog, new Date(expiredToken.expiresAt.getTime() + 1));

    // A handful of other, unrelated denial paths.
    enforceToken(expiredToken.id, "payment:charge", tokenStore, auditLog, new Date(expiredToken.expiresAt.getTime() - 1)); // out_of_scope, before expiry
    enforceToken("not-a-real-token", "email:send", tokenStore, auditLog); // unknown_token

    const shortLivedParent = issueToken({ subject: "agent-2", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    delegateToken(shortLivedParent.id, "sub-agent", ["email:send", "sms:send"], 60, tokenStore, auditLog); // exceeds_parent_scope

    const pendingRequest = requestToken({ subject: "agent-3", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);
    denyRequest(pendingRequest.id, requestStore, auditLog, "approver-1", "unverified_subject");

    const noScopeToken = issueToken({ subject: "agent-4", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    accessCustomerData(noScopeToken.id, "cust-001", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id); // out_of_scope again, different subsystem

    const customerReadToken = issueToken({ subject: "agent-5", scope: ["customer:read"], ttlSeconds: 300 }, tokenStore);
    accessCustomerData(customerReadToken.id, "not-a-real-customer", tokenStore, auditLog, customerRegistry, redactionRuleStore, rule.id); // unknown_customer — reaches this branch only because customer:read is actually present

    const denialEntries = auditLog.entries().filter((e) => e.decision === "denied" || e.decision === "request_denied");

    // Every one of these denials carries a distinct, non-empty reasonCode.
    expect(denialEntries.length).toBeGreaterThanOrEqual(7);
    for (const entry of denialEntries) {
      expect(entry.reasonCode).toBeTruthy();
    }

    const reasonCodes = denialEntries.map((e) => e.reasonCode);
    // The expiration case specifically must say "expired" — the acceptance
    // criterion's exact wording, checked directly, not inferred.
    expect(reasonCodes).toContain("expired");
    expect(reasonCodes).toContain("out_of_scope");
    expect(reasonCodes).toContain("unknown_token");
    expect(reasonCodes).toContain("exceeds_parent_scope");
    expect(reasonCodes).toContain("unverified_subject");
    expect(reasonCodes).toContain("unknown_customer");

    // "Distinct" checked for real: at least this many different values
    // actually appear, not every denial collapsing onto one generic code.
    expect(new Set(reasonCodes).size).toBeGreaterThanOrEqual(6);
  });
});
