import { describe, expect, it, vi } from "vitest";
import { AuditLog } from "./auditLog.js";
import { accessMockEndpoint } from "./mockEndpointAccess.js";
import { MockEndpointRegistry } from "./mockEndpoints.js";
import { issueToken, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";

function setup() {
  return { store: new TokenStore(), auditLog: new AuditLog(), registry: new MockEndpointRegistry() };
}

// Fast config for tests — the numbers themselves are the whole point of
// STORY-005's "no hardcoded magic" follow-up, so tests use their own small
// values rather than waiting out the real defaults.
const FAST_CONFIG = { timeoutMs: 50, maxAttempts: 2, retryDelayMs: 5 };

describe("accessMockEndpoint", () => {
  // Acceptance: "Given a valid token, when the token is used to access a
  // mock endpoint, then the action is allowed."
  it("allows and calls the endpoint for a valid, in-scope token", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    const result = await accessMockEndpoint(token.id, "email", "send", store, auditLog, registry, FAST_CONFIG);

    expect(result).toEqual({
      allowed: true,
      outcome: "success",
      result: { system: "email", verb: "send", detail: "email:send succeeded" },
    });
  });

  // Trust: "the action and its outcome are logged" — both facts, as two
  // entries: the gateway's decision, and the integration's outcome.
  it("logs both the gateway decision and the endpoint outcome", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);

    await accessMockEndpoint(token.id, "email", "send", store, auditLog, registry, FAST_CONFIG);

    const entries = auditLog.entries();
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ action: "email:send", decision: "allowed" });
    expect(entries[0]?.outcome).toBeUndefined(); // the enforceToken entry — gateway only, no outcome yet
    expect(entries[1]).toMatchObject({ action: "email:send", decision: "allowed", outcome: "success" });
  });

  // Acceptance: "Given an invalid token, when used, then denied." Three real
  // ways a token can be invalid, none of which should ever reach the endpoint.
  it("denies an unknown token id and never calls the endpoint", async () => {
    const { store, auditLog, registry } = setup();
    const spy = vi.spyOn(registry, "call");

    const result = await accessMockEndpoint("not-a-real-id", "email", "send", store, auditLog, registry, FAST_CONFIG);

    expect(result).toEqual({ allowed: false, reasonCode: "unknown_token" });
    expect(spy).not.toHaveBeenCalled();
  });

  it("denies a revoked token and never calls the endpoint", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["email:send"], ttlSeconds: 300 }, store);
    revokeToken(token.id, store, auditLog, "compromised");
    const spy = vi.spyOn(registry, "call");

    const result = await accessMockEndpoint(token.id, "email", "send", store, auditLog, registry, FAST_CONFIG);

    expect(result).toEqual({ allowed: false, reasonCode: "revoked" });
    expect(spy).not.toHaveBeenCalled();
  });

  it("denies a token that lacks the scope for this action and never calls the endpoint", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["crm:read"], ttlSeconds: 300 }, store);
    const spy = vi.spyOn(registry, "call");

    const result = await accessMockEndpoint(token.id, "payment", "charge", store, auditLog, registry, FAST_CONFIG);

    expect(result).toEqual({ allowed: false, reasonCode: "out_of_scope" });
    expect(spy).not.toHaveBeenCalled();
  });

  it("does not log an outcome entry for a denied access — only the gateway's own denial", async () => {
    const { store, auditLog, registry } = setup();
    await accessMockEndpoint("not-a-real-id", "email", "send", store, auditLog, registry, FAST_CONFIG);

    expect(auditLog.entries()).toHaveLength(1);
    expect(auditLog.entries()[0]?.outcome).toBeUndefined();
  });

  // Failure path: "Endpoint is unreachable" — the gateway still allows the
  // valid token through; the failure is downstream, and is what gets logged.
  it("logs an unreachable outcome, after retrying, when the endpoint is down", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["payment:charge"], ttlSeconds: 300 }, store);
    registry.setDown("payment", true);
    const spy = vi.spyOn(registry, "call");

    const result = await accessMockEndpoint(token.id, "payment", "charge", store, auditLog, registry, FAST_CONFIG);

    expect(result).toEqual({ allowed: true, outcome: "unreachable" });
    expect(spy).toHaveBeenCalledTimes(FAST_CONFIG.maxAttempts);
    const outcomeEntry = auditLog.entries().find((e) => e.outcome !== undefined);
    expect(outcomeEntry).toMatchObject({ decision: "allowed", outcome: "unreachable" });
  });

  it("recovers on retry if the endpoint comes back up between attempts", async () => {
    const { store, auditLog, registry } = setup();
    const token = issueToken({ subject: "agent-42", scope: ["crm:read"], ttlSeconds: 300 }, store);
    registry.setDown("crm", true);
    const spy = vi.spyOn(registry, "call").mockImplementationOnce(async () => {
      throw new Error("down for this call only");
    });
    // Second call onward uses the real (now not-down) implementation.
    registry.setDown("crm", false);

    const result = await accessMockEndpoint(token.id, "crm", "read", store, auditLog, registry, FAST_CONFIG);

    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.outcome).toBe("success");
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
