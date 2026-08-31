import { describe, expect, it } from "vitest";
import { AuditLog } from "./auditLog.js";
import {
  AgentIdentityStore,
  DuplicateAgentIdentityError,
  InvalidAgentIdentityError,
  authenticateAgent,
  registerAgentIdentity,
} from "./agentIdentity.js";

function setup() {
  return { store: new AgentIdentityStore(), auditLog: new AuditLog() };
}

describe("registerAgentIdentity", () => {
  it("creates an identity and returns a credential in the id.secret shape", async () => {
    const { store, auditLog } = setup();
    const { identity, credential } = await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);

    expect(identity.subject).toBe("billing-agent");
    expect(credential.startsWith(`${identity.id}.`)).toBe(true);
    expect(store.get(identity.id)).toEqual(identity);
  });

  it("never stores the raw secret — only its hash", async () => {
    const { store, auditLog } = setup();
    const { identity, credential } = await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);
    const rawSecret = credential.split(".")[1];

    expect(identity.secretHash).not.toContain(rawSecret);
  });

  it("logs the registration with the registering operator as actor", async () => {
    const { store, auditLog } = setup();
    await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);

    expect(auditLog.entries()).toContainEqual(
      expect.objectContaining({ decision: "agent_identity_registered", actor: "operator-1", subject: "billing-agent" }),
    );
  });

  it("refuses an empty subject", async () => {
    const { store, auditLog } = setup();
    await expect(registerAgentIdentity({ subject: "" }, "operator-1", store, auditLog)).rejects.toThrow(InvalidAgentIdentityError);
  });

  it("refuses a duplicate subject", async () => {
    const { store, auditLog } = setup();
    await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);
    await expect(registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog)).rejects.toThrow(
      DuplicateAgentIdentityError,
    );
  });
});

describe("authenticateAgent", () => {
  it("authenticates with the real credential and returns the matching identity", async () => {
    const { store, auditLog } = setup();
    const { identity, credential } = await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);

    const result = await authenticateAgent(credential, store);
    expect(result?.id).toBe(identity.id);
    expect(result?.subject).toBe("billing-agent");
  });

  it("refuses a credential with the wrong secret for a real id", async () => {
    const { store, auditLog } = setup();
    const { identity } = await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);

    expect(await authenticateAgent(`${identity.id}.wrong-secret`, store)).toBeNull();
  });

  it("refuses a credential for an id that was never registered", async () => {
    const { store } = setup();
    expect(await authenticateAgent("not-a-real-id.some-secret", store)).toBeNull();
  });

  it("refuses a malformed credential (no dot) without throwing", async () => {
    const { store } = setup();
    await expect(authenticateAgent("not-a-real-credential-at-all", store)).resolves.toBeNull();
  });

  it("refuses a credential with an empty secret", async () => {
    const { store, auditLog } = setup();
    const { identity } = await registerAgentIdentity({ subject: "billing-agent" }, "operator-1", store, auditLog);

    expect(await authenticateAgent(`${identity.id}.`, store)).toBeNull();
  });

  // The split is on the FIRST dot only — a secret value containing further
  // dots (not how this store generates them, hex never has dots, but the
  // parsing itself should still be correct as a matter of design) must
  // still be treated as part of the secret, not truncated.
  it("splits on the first dot only, treating everything after it as the secret", async () => {
    const { store } = setup();
    // Construct a contrived case directly through the store to prove the
    // parser's behavior independent of how secrets happen to be generated.
    const { hashPassword } = await import("./passwordHash.js");
    const secretWithDots = "part1.part2.part3";
    const secretHash = await hashPassword(secretWithDots);
    store.save({ id: "agent-x", subject: "dotted-secret-agent", secretHash, createdBy: "operator-1", createdAt: new Date() });

    const result = await authenticateAgent(`agent-x.${secretWithDots}`, store);
    expect(result?.subject).toBe("dotted-secret-agent");
  });
});
