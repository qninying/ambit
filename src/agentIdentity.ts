// ADR-009 hardening: closes requester-identity spoofing on POST /requests.
// Before this, "subject" was whatever string the caller put in the request
// body — anyone could submit a request claiming to be a trusted agent's
// name. An Agent Identity is a real, pre-registered credential: an
// operator (already authenticated via sessionToken.ts) registers a known
// agent, gets a secret back exactly once, and from then on "subject" on a
// submitted request is DERIVED from that credential, never client-supplied.
//
// Credential shape mirrors AWS's access-key-id + secret split, not a bare
// secret: `<identity id>.<random secret>`. That split makes lookup O(1) by
// id instead of having to re-verify a salted hash against every registered
// agent to find which one matches (scrypt hashes are salted, so you can't
// index by the hash itself).

import { randomBytes } from "node:crypto";
import type { AuditLog } from "./auditLog.js";
import { hashPassword, verifyPassword } from "./passwordHash.js";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

export interface AgentIdentity {
  id: string;
  subject: string;
  secretHash: string;
  createdBy: string;
  createdAt: Date;
}

export interface AgentIdentityInput {
  subject: string;
}

export class InvalidAgentIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidAgentIdentityError";
  }
}

export class DuplicateAgentIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DuplicateAgentIdentityError";
  }
}

function reviveAgentIdentity(raw: unknown): AgentIdentity {
  const i = raw as AgentIdentity & { createdAt: string };
  return { ...i, createdAt: new Date(i.createdAt) };
}

export class AgentIdentityStore {
  #identities = new Map<string, AgentIdentity>();
  #persistTo?: string;

  // ADR-014: only secretHash is ever persisted — the same field that was
  // already the only thing kept in memory beyond the one-time registration
  // response. No new secret-handling risk here.
  constructor(persistTo?: string) {
    this.#persistTo = persistTo;
    if (persistTo) {
      for (const identity of rehydrateJsonLines(persistTo, reviveAgentIdentity)) {
        this.#identities.set(identity.id, identity);
      }
    }
  }

  save(identity: AgentIdentity): void {
    this.#identities.set(identity.id, identity);
    if (this.#persistTo) appendJsonLine(this.#persistTo, identity);
  }

  get(id: string): AgentIdentity | undefined {
    return this.#identities.get(id);
  }

  list(): AgentIdentity[] {
    return [...this.#identities.values()];
  }

  findBySubject(subject: string): AgentIdentity | undefined {
    return [...this.#identities.values()].find((i) => i.subject === subject);
  }
}

function validate(input: AgentIdentityInput, store: AgentIdentityStore): void {
  if (!input.subject || input.subject.trim().length === 0) {
    throw new InvalidAgentIdentityError("subject is required");
  }
  if (store.findBySubject(input.subject)) {
    throw new DuplicateAgentIdentityError(`an agent identity for subject "${input.subject}" already exists`);
  }
}

export interface RegisteredAgentIdentity {
  identity: AgentIdentity;
  // The raw credential — returned ONCE, here, at registration. Never
  // retrievable again; only its hash is ever stored.
  credential: string;
}

export async function registerAgentIdentity(
  input: AgentIdentityInput,
  createdBy: string,
  store: AgentIdentityStore,
  auditLog: AuditLog,
  now: Date = new Date(),
): Promise<RegisteredAgentIdentity> {
  validate(input, store);
  const id = crypto.randomUUID();
  const secret = randomBytes(32).toString("hex");
  const secretHash = await hashPassword(secret);
  const identity: AgentIdentity = { id, subject: input.subject, secretHash, createdBy, createdAt: now };
  store.save(identity);
  auditLog.record({ subject: input.subject, action: "register_agent_identity", decision: "agent_identity_registered", actor: createdBy }, now);
  return { identity, credential: `${id}.${secret}` };
}

// Never throws — same "always a result, never a crash" contract every
// other gateway-shaped check in this codebase holds. A malformed or
// unrecognized credential is just null, not an exception.
export async function authenticateAgent(credential: string, store: AgentIdentityStore): Promise<AgentIdentity | null> {
  const dotIndex = credential.indexOf(".");
  if (dotIndex <= 0) return null;
  const id = credential.slice(0, dotIndex);
  const secret = credential.slice(dotIndex + 1);
  if (!secret) return null;

  const identity = store.get(id);
  if (!identity) return null;

  const matches = await verifyPassword(secret, identity.secretHash);
  return matches ? identity : null;
}
