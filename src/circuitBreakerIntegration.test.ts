// circuitBreaker.test.ts proves the state machine itself is correct in
// isolation. This file proves the actual wiring: a real CircuitBreaker
// shared across TokenStore and PolicyStore genuinely changes what
// enforceToken/delegateToken/issueToken/createPolicy do when it trips —
// each of REQ-008's three acceptance criteria, exercised through the real
// call paths a request actually takes, not just asserted against the
// breaker directly.

import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import { CircuitBreaker } from "./circuitBreaker.js";
import { TokenStore } from "./tokenStore.js";
import { PolicyStore, createPolicy } from "./policy.js";
import { enforceToken, issueToken } from "./token.js";
import { delegateToken } from "./delegation.js";
import { approveRequest, requestToken } from "./tokenRequest.js";
import { RequestStore } from "./requestStore.js";
import { AnomalyDetector } from "./anomalyDetector.js";

function setup(breakerConfig = { failureThreshold: 2, cooldownMs: 1_000 }) {
  const auditLog = new AuditLog();
  const breaker = new CircuitBreaker(breakerConfig, (change) => {
    if (change.to === "open") {
      auditLog.record({ subject: "system", action: "policy_token_store", decision: "circuit_opened", reasonCode: change.reason });
    } else if (change.to === "closed") {
      auditLog.record({ subject: "system", action: "policy_token_store", decision: "circuit_closed", reasonCode: change.reason });
    }
  });
  return {
    auditLog,
    breaker,
    tokenStore: new TokenStore(breaker),
    policyStore: new PolicyStore(breaker),
    requestStore: new RequestStore(),
    anomalyDetector: new AnomalyDetector(),
  };
}

describe("REQ-008: fail-closed circuit breaker, wired into the real call paths", () => {
  // Acceptance: "Given the Store is reachable, when a request is made, then
  // it is processed." — a breaker being present must not change normal
  // behavior at all.
  it("does not change normal behavior when the store is reachable", () => {
    const { tokenStore, auditLog } = setup();
    const token = issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    const decision = enforceToken(token.id, "email:send", tokenStore, auditLog);
    expect(decision).toEqual({ allowed: true });
  });

  // Acceptance: "Given the Policy & Token Store is unreachable, when a
  // request is made, then it is denied." — enforceToken's half.
  it("enforceToken denies with store_unavailable, never throws, once the breaker is open", () => {
    const { tokenStore, breaker, auditLog } = setup();
    breaker.simulateOutage(true);
    // Trip it for real via two failing calls, matching the configured threshold.
    expect(() => tokenStore.get("anything")).toThrow();
    expect(() => tokenStore.get("anything")).toThrow();
    expect(breaker.state()).toBe("open");

    const decision = enforceToken("some-token-id", "email:send", tokenStore, auditLog);
    expect(decision).toEqual({
      allowed: false,
      reasonCode: "store_unavailable",
      message: expect.stringContaining("some-token-id"),
    });
    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ decision: "denied", reasonCode: "store_unavailable" }),
    );
  });

  // delegateToken's half of the same guarantee.
  it("delegateToken denies with store_unavailable, never throws, once the breaker is open", () => {
    const { tokenStore, breaker, auditLog } = setup();
    const parent = issueToken({ subject: "agent-1", scope: ["email:send", "sms:send"], ttlSeconds: 300 }, tokenStore);

    breaker.simulateOutage(true);
    expect(() => tokenStore.get("x")).toThrow();
    expect(() => tokenStore.get("x")).toThrow();
    expect(breaker.state()).toBe("open");

    const decision = delegateToken(parent.id, "sub-agent-1", ["email:send"], 60, tokenStore, auditLog);
    expect(decision).toEqual({ approved: false, reasonCode: "store_unavailable" });
  });

  // issueToken's half — reached through approveRequest, the real path a
  // token actually gets issued through in this system, and proves the
  // request stays pending (not consumed) so a retry once the store
  // recovers is still possible, same as the existing policy-violation path.
  it("approveRequest denies and logs, leaving the request pending, when the store is unreachable at issuance time", () => {
    const { tokenStore, requestStore, anomalyDetector, auditLog, breaker } = setup();
    const pending = requestToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, requestStore, anomalyDetector, auditLog);

    breaker.simulateOutage(true);
    expect(() => tokenStore.get("x")).toThrow();
    expect(() => tokenStore.get("x")).toThrow();
    expect(breaker.state()).toBe("open");

    expect(() => approveRequest(pending.id, requestStore, tokenStore, auditLog, "approver-1")).toThrow();
    expect(requestStore.get(pending.id)?.status).toBe("pending");
    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ requestId: pending.id, decision: "request_denied", actor: "approver-1" }),
    );
  });

  // createPolicy's half — the "Policy" side of "Policy & Token Store".
  it("createPolicy throws (propagating CircuitOpenError) when the store is unreachable", () => {
    const { policyStore, auditLog, breaker } = setup();
    breaker.simulateOutage(true);
    expect(() => policyStore.get("x")).toThrow();
    expect(() => policyStore.get("x")).toThrow();
    expect(breaker.state()).toBe("open");

    expect(() =>
      createPolicy({ name: "Email only", allowedScope: ["email:send"], maxTtlSeconds: 3600 }, "policy-manager-1", policyStore, auditLog),
    ).toThrow();
  });

  // Trust: circuit-breaker actions are logged — the actual audit-visible
  // consequence of the breaker tripping and recovering, end to end.
  it("logs circuit_opened when the breaker trips and circuit_closed when it recovers", () => {
    const { tokenStore, breaker, auditLog } = setup();
    breaker.simulateOutage(true);
    expect(() => tokenStore.get("x")).toThrow();
    expect(() => tokenStore.get("x")).toThrow();
    expect(auditLog.entries()).toContainEqual(expect.objectContaining({ decision: "circuit_opened" }));

    breaker.simulateOutage(false);
    // Cooldown hasn't elapsed by wall-clock `now` in this test, so force the
    // probe via an explicit future `now` the way circuitBreaker.test.ts does.
    breaker.execute(() => "probe", new Date(Date.now() + 2_000));
    expect(auditLog.entries()).toContainEqual(expect.objectContaining({ decision: "circuit_closed" }));
  });

  // The other direction of "actions are logged": a store that never trips
  // must never log a circuit event at all — logging on every call would
  // just be noise, not trust-relevant signal.
  it("does not log any circuit event when the store never becomes unreachable", () => {
    const { tokenStore, auditLog } = setup();
    issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, tokenStore);
    expect(auditLog.entries().some((e) => e.decision === "circuit_opened" || e.decision === "circuit_closed")).toBe(false);
  });
});
