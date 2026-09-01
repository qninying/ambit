// Same pattern as TokenStore: the single source of truth for pending consent
// requests, looked up fresh by id rather than trusted from a stale copy. This
// is what makes double-approving the same request fail instead of silently
// issuing two tokens for one request (the idempotency guardrail in CLAUDE.md).
//
// ADR-014: optionally persisted to an append-only JSONL file. One field is
// deliberately NEVER written to disk: `tokenSecret` (ADR-013's transient,
// one-time-claimable token secret). Persisting it — even correctly cleared
// on a later line — would put the plaintext secret on disk, if only
// briefly, which is exactly what ADR-013's whole design exists to avoid.
// The in-memory Map still carries it (claimTokenSecret() needs it there);
// only the durable copy strips it.

import type { PendingRequest } from "./tokenRequest.js";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

function revivePendingRequest(raw: unknown): PendingRequest {
  const r = raw as PendingRequest & { requestedAt: string };
  return { ...r, requestedAt: new Date(r.requestedAt) };
}

// A rehydrated request can never carry a claimable secret — if it wasn't
// claimed before a restart, it no longer can be (the plaintext never
// touched disk in the first place, by design). Framed here as an explicit
// fact, not a silent side effect of the field simply never being written.
function forPersistence(request: PendingRequest): Omit<PendingRequest, "tokenSecret"> {
  const { tokenSecret: _tokenSecret, ...rest } = request;
  return rest;
}

export class RequestStore {
  #requests = new Map<string, PendingRequest>();
  #persistTo?: string;

  constructor(persistTo?: string) {
    this.#persistTo = persistTo;
    if (persistTo) {
      for (const request of rehydrateJsonLines(persistTo, revivePendingRequest)) {
        this.#requests.set(request.id, request);
      }
    }
  }

  save(request: PendingRequest): void {
    this.#requests.set(request.id, request);
    if (this.#persistTo) appendJsonLine(this.#persistTo, forPersistence(request));
  }

  get(id: string): PendingRequest | undefined {
    return this.#requests.get(id);
  }

  // For the Consent UI: what actually needs an approver's attention right now.
  pending(): PendingRequest[] {
    return [...this.#requests.values()].filter((r) => r.status === "pending");
  }

  // Scoped to (subject, idempotencyKey) rather than idempotencyKey alone —
  // two different subjects are free to reuse the same key without colliding.
  // Used by requestToken() to make a submit-with-key call safe to retry:
  // finding an existing record here means "return what's already there,"
  // not "create another one."
  findByIdempotencyKey(subject: string, idempotencyKey: string): PendingRequest | undefined {
    return [...this.#requests.values()].find((r) => r.subject === subject && r.idempotencyKey === idempotencyKey);
  }
}
