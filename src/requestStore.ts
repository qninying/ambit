// Same pattern as TokenStore: the single source of truth for pending consent
// requests, looked up fresh by id rather than trusted from a stale copy. This
// is what makes double-approving the same request fail instead of silently
// issuing two tokens for one request (the idempotency guardrail in CLAUDE.md).

import type { PendingRequest } from "./tokenRequest.js";

export class RequestStore {
  #requests = new Map<string, PendingRequest>();

  save(request: PendingRequest): void {
    this.#requests.set(request.id, request);
  }

  get(id: string): PendingRequest | undefined {
    return this.#requests.get(id);
  }

  // For the Consent UI: what actually needs an approver's attention right now.
  pending(): PendingRequest[] {
    return [...this.#requests.values()].filter((r) => r.status === "pending");
  }
}
