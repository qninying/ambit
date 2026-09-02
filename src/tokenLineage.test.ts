import { describe, expect, it } from "vitest";
import { AnomalyDetector } from "./anomalyDetector.js";
import { AuditLog } from "./auditLog.js";
import { PolicyStore, createPolicy } from "./policy.js";
import { RequestStore } from "./requestStore.js";
import { UnknownTokenError, getTokenLineage, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { approveRequest, claimTokenSecret, requestToken } from "./tokenRequest.js";
import { delegateToken } from "./delegation.js";

function setup() {
  return {
    requestStore: new RequestStore(),
    tokenStore: new TokenStore(),
    auditLog: new AuditLog(),
    anomalyDetector: new AnomalyDetector(),
    policyStore: new PolicyStore(),
  };
}

// The only two ways a real token comes into existence — a human-approved
// request (a root) or a possession-based delegation from an existing one
// (a child). Building fixtures through these real functions, not by
// hand-constructing Token objects, is what makes these tests prove the real
// origin-lookup logic against a real audit trail, not a fixture that just
// happens to look right.
async function issueRootToken(deps: ReturnType<typeof setup>, approver: string, policyId?: string) {
  const pending = requestToken(
    { subject: "root-agent", scope: ["email:send", "crm:read", "payment:charge"], ttlSeconds: 3600 },
    deps.requestStore,
    deps.anomalyDetector,
    deps.auditLog,
  );
  const token = await approveRequest(pending.id, deps.requestStore, deps.tokenStore, deps.auditLog, approver, policyId, deps.policyStore);
  // approveRequest() deliberately never returns the plaintext secret
  // (ADR-013) — claiming it through the real one-time path, same as any
  // real requester would, rather than reaching into internals.
  const { secret } = claimTokenSecret(pending.id, "root-agent", deps.requestStore, deps.auditLog);
  return { requestId: pending.id, token, secret };
}

describe("getTokenLineage", () => {
  it("throws UnknownTokenError for a token that doesn't exist", () => {
    const { tokenStore, auditLog } = setup();
    expect(() => getTokenLineage("no-such-token", tokenStore, auditLog)).toThrow(UnknownTokenError);
  });

  it("a root token's chain is just itself", async () => {
    const deps = setup();
    const { token } = await issueRootToken(deps, "approver-1");

    const lineage = getTokenLineage(token.id, deps.tokenStore, deps.auditLog);
    expect(lineage.chain).toHaveLength(1);
    expect(lineage.chain[0]!.id).toBe(token.id);
  });

  it("a root token's origin cites the real request, policy, and approver", async () => {
    const deps = setup();
    const policy = createPolicy(
      { name: "Standard", allowedScope: ["email:send", "crm:read", "payment:charge"], maxTtlSeconds: 3600 },
      "policy-author",
      deps.policyStore,
      deps.auditLog,
    );
    const { requestId, token } = await issueRootToken(deps, "approver-1", policy.id);

    const lineage = getTokenLineage(token.id, deps.tokenStore, deps.auditLog);
    expect(lineage.origin).toEqual({ requestId, policyId: policy.id, approver: "approver-1" });
  });

  it("a root token issued with no policy has an origin with no policyId, not a fabricated one", async () => {
    const deps = setup();
    const { requestId, token } = await issueRootToken(deps, "approver-1");

    const lineage = getTokenLineage(token.id, deps.tokenStore, deps.auditLog);
    expect(lineage.origin).toEqual({ requestId, policyId: undefined, approver: "approver-1" });
  });

  it("a multi-level delegation chain renders root-first, in real derivation order", async () => {
    const deps = setup();
    const { token: root, secret: rootSecret } = await issueRootToken(deps, "approver-1");

    const childDecision = await delegateToken(root.id, rootSecret, "child-agent", ["email:send", "crm:read"], 1800, deps.tokenStore, deps.auditLog);
    if (!childDecision.approved) throw new Error("expected delegation to succeed");
    const grandchildDecision = await delegateToken(
      childDecision.token.id,
      childDecision.secret,
      "grandchild-agent",
      ["email:send"],
      900,
      deps.tokenStore,
      deps.auditLog,
    );
    if (!grandchildDecision.approved) throw new Error("expected delegation to succeed");

    const lineage = getTokenLineage(grandchildDecision.token.id, deps.tokenStore, deps.auditLog);
    expect(lineage.chain.map((t) => t.id)).toEqual([root.id, childDecision.token.id, grandchildDecision.token.id]);
    expect(lineage.chain.map((t) => t.subject)).toEqual(["root-agent", "child-agent", "grandchild-agent"]);
    // The real origin belongs to the root, regardless of how deep the
    // token actually asked about sits in the chain.
    expect(lineage.origin?.approver).toBe("approver-1");
  });

  it("shows a revoked ancestor's real status and reason on its own link in the chain — 'how it changed'", async () => {
    const deps = setup();
    const { token: root, secret: rootSecret } = await issueRootToken(deps, "approver-1");
    const childDecision = await delegateToken(root.id, rootSecret, "child-agent", ["email:send", "crm:read"], 1800, deps.tokenStore, deps.auditLog);
    if (!childDecision.approved) throw new Error("expected delegation to succeed");

    revokeToken(childDecision.token.id, deps.tokenStore, deps.auditLog, "compromised");

    const lineage = getTokenLineage(childDecision.token.id, deps.tokenStore, deps.auditLog);
    const child = lineage.chain[1]!;
    expect(child.status).toBe("revoked");
    expect(child.revocationReason).toBe("compromised");
    expect(lineage.chain[0]!.status).toBe("active"); // the root itself is untouched
  });

  it("shows a cascaded revocation's real reason on the grandchild's own link, distinct from the direct revocation", async () => {
    const deps = setup();
    const { token: root, secret: rootSecret } = await issueRootToken(deps, "approver-1");
    const childDecision = await delegateToken(root.id, rootSecret, "child-agent", ["email:send", "crm:read"], 1800, deps.tokenStore, deps.auditLog);
    if (!childDecision.approved) throw new Error("expected delegation to succeed");
    const grandchildDecision = await delegateToken(
      childDecision.token.id,
      childDecision.secret,
      "grandchild-agent",
      ["email:send"],
      900,
      deps.tokenStore,
      deps.auditLog,
    );
    if (!grandchildDecision.approved) throw new Error("expected delegation to succeed");

    revokeToken(childDecision.token.id, deps.tokenStore, deps.auditLog, "compromised");

    const lineage = getTokenLineage(grandchildDecision.token.id, deps.tokenStore, deps.auditLog);
    expect(lineage.chain[1]!.revocationReason).toBe("compromised");
    expect(lineage.chain[2]!.revocationReason).toBe("parent_revoked");
  });
});
