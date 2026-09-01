// REQ-009: field-level redaction. A rule maps a sensitive field name to the
// SPECIFIC scope required to see it unredacted — not a blanket "can this
// token see customer data at all" (that's the Enforcement Gateway's job,
// reused as-is in customerDataAccess.ts, not reinvented here). A field not
// listed in sensitiveFields is never redacted; every field that IS listed
// is redacted unless the token's own scope includes its required scope.

import type { AuditLog } from "./auditLog.js";
import type { CustomerRecord } from "./customerData.js";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

export interface RedactionRule {
  id: string;
  name: string;
  sensitiveFields: Record<string, string>; // field name -> required scope
  authoredBy: string;
  createdAt: Date;
}

export interface RedactionRuleInput {
  name: string;
  sensitiveFields: Record<string, string>;
}

export class InvalidRedactionRuleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidRedactionRuleError";
  }
}

function reviveRedactionRule(raw: unknown): RedactionRule {
  const r = raw as RedactionRule & { createdAt: string };
  return { ...r, createdAt: new Date(r.createdAt) };
}

export class RedactionRuleStore {
  #rules = new Map<string, RedactionRule>();
  #persistTo?: string;

  constructor(persistTo?: string) {
    this.#persistTo = persistTo;
    if (persistTo) {
      for (const rule of rehydrateJsonLines(persistTo, reviveRedactionRule)) {
        this.#rules.set(rule.id, rule);
      }
    }
  }

  save(rule: RedactionRule): void {
    this.#rules.set(rule.id, rule);
    if (this.#persistTo) appendJsonLine(this.#persistTo, rule);
  }

  get(id: string): RedactionRule | undefined {
    return this.#rules.get(id);
  }

  list(): RedactionRule[] {
    return [...this.#rules.values()];
  }
}

function validate(input: RedactionRuleInput): void {
  if (!input.name || input.name.trim().length === 0) {
    throw new InvalidRedactionRuleError("name is required");
  }
  const fields = Object.entries(input.sensitiveFields);
  if (fields.length === 0) {
    throw new InvalidRedactionRuleError("sensitiveFields must protect at least one field — an empty rule protects nothing");
  }
  for (const [field, requiredScope] of fields) {
    if (!field || field.trim().length === 0) {
      throw new InvalidRedactionRuleError("a sensitive field name cannot be empty");
    }
    if (!requiredScope || requiredScope.trim().length === 0) {
      throw new InvalidRedactionRuleError(`field "${field}" has no requiredScope — a field with an empty required scope can never be un-redacted, which is likely a misconfiguration, not an intentional permanent redaction`);
    }
  }
}

// Acceptance: "Given a request for customer data, when the data is
// accessed, then sensitive fields are redacted." — this closes it: proves
// a rule that doesn't actually protect anything is rejected up front,
// rather than silently accepted and only discovered as a leak later.
export function createRedactionRule(
  input: RedactionRuleInput,
  authoredBy: string,
  store: RedactionRuleStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): RedactionRule {
  validate(input);
  const rule: RedactionRule = {
    id: crypto.randomUUID(),
    name: input.name,
    sensitiveFields: input.sensitiveFields,
    authoredBy,
    createdAt: now,
  };
  store.save(rule);
  auditLog.record({ subject: authoredBy, action: "create_redaction_rule", decision: "redaction_rule_created", reasonCode: rule.id }, now);
  return rule;
}

export const REDACTION_MASK = "[REDACTED]";

export interface RedactionResult {
  data: CustomerRecord;
  redactedFields: string[];
}

// Pure — no I/O, no logging. customerDataAccess.ts owns turning this
// result into the audit trail; this only owns the redaction logic itself.
export function applyRedaction(record: CustomerRecord, rule: RedactionRule, tokenScope: string[]): RedactionResult {
  const data = { ...record } as Record<string, unknown>;
  const redactedFields: string[] = [];
  for (const [field, requiredScope] of Object.entries(rule.sensitiveFields)) {
    if (!(field in data)) continue; // rule may name fields this record type doesn't have
    if (!tokenScope.includes(requiredScope)) {
      data[field] = REDACTION_MASK;
      redactedFields.push(field);
    }
  }
  return { data: data as unknown as CustomerRecord, redactedFields };
}
