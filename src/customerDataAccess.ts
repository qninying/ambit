// REQ-009: the actual access layer — reuses the Enforcement Gateway
// (token.ts) for the coarse "is this token allowed to touch customer data
// at all" decision, exactly the way STORY-005's mockEndpointAccess.ts
// reuses it for mock endpoints. Redaction (redaction.ts) is a separate,
// finer-grained layer applied only once that gate has already said yes —
// this file is what wires the two together and owns the audit trail for
// both halves.

import type { AuditLog } from "./auditLog.js";
import { enforceToken } from "./token.js";
import type { TokenStore } from "./tokenStore.js";
import type { CustomerDataRegistry, CustomerRecord } from "./customerData.js";
import { applyRedaction, type RedactionRuleStore } from "./redaction.js";

export type CustomerDataAccessResult =
  | { allowed: true; data: CustomerRecord; redactedFields: string[] }
  | {
      allowed: false;
      reasonCode: "revoked" | "expired" | "out_of_scope" | "unknown_token" | "store_unavailable" | "invalid_credential" | "unknown_customer" | "redaction_rule_unavailable";
      message: string;
    };

const CUSTOMER_READ_ACTION = "customer:read";

export async function accessCustomerData(
  tokenId: string,
  providedSecret: string,
  customerId: string,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  customerRegistry: CustomerDataRegistry,
  redactionRuleStore: RedactionRuleStore,
  redactionRuleId: string,
  now: Date = new Date(),
): Promise<CustomerDataAccessResult> {
  // The coarse gate. Nothing about REQ-004/REQ-006/REQ-018's guardrails is
  // reimplemented here — a denial from enforceToken (with its own detailed
  // STORY-010 message, and ADR-013's possession check) IS the denial for
  // "lacks proper authorization."
  const decision = await enforceToken(tokenId, providedSecret, CUSTOMER_READ_ACTION, tokenStore, auditLog, now);
  if (!decision.allowed) {
    return decision;
  }

  const customer = customerRegistry.get(customerId);
  if (!customer) {
    const message = `No customer found with id "${customerId}".`;
    auditLog.record({ tokenId, action: CUSTOMER_READ_ACTION, subject: "unknown", decision: "denied", reasonCode: "unknown_customer", message }, now);
    return { allowed: false, reasonCode: "unknown_customer", message };
  }

  // A redaction rule that can't be resolved is a misconfiguration, not a
  // reason to fall back to returning the record unredacted. Fail closed on
  // the side of protecting the data, same "can't confirm -> deny" guardrail
  // philosophy as every other gateway decision in this codebase — the one
  // wrong direction here would be silently leaking PII because a lookup
  // failed.
  const rule = redactionRuleStore.get(redactionRuleId);
  if (!rule) {
    const message = `Redaction rule "${redactionRuleId}" could not be resolved — denying access rather than returning customer data with an unknown redaction policy applied.`;
    auditLog.record({ tokenId, action: CUSTOMER_READ_ACTION, subject: "unknown", decision: "denied", reasonCode: "redaction_rule_unavailable", message }, now);
    return { allowed: false, reasonCode: "redaction_rule_unavailable", message };
  }

  // enforceToken only returns allowed:true when it found the token, so this
  // is always defined here — narrowed for TypeScript, not a real branch.
  // Same defensive-fallback style as mockEndpointAccess.ts, not a `!`
  // assertion, so a truly impossible case degrades to "no elevated scope"
  // rather than a crash.
  const token = tokenStore.get(tokenId);
  const tokenScope = token ? token.scope : [];
  const subject = token ? token.subject : "unknown";
  const { data, redactedFields } = applyRedaction(customer, rule, tokenScope);

  // Two entries, deliberately (ADR-005): the access decision (already
  // logged by enforceToken above, as "allowed") and this — the redaction
  // outcome — are two different facts. "Access happened" doesn't tell an
  // auditor what was actually visible; this does.
  auditLog.record({
    tokenId,
    subject,
    action: CUSTOMER_READ_ACTION,
    decision: "data_accessed",
    redactedFields,
  }, now);

  return { allowed: true, data, redactedFields };
}
