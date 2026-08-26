// The single source of truth for token state. enforceToken and revokeToken
// both read/write through this rather than trusting whatever Token object a
// caller happens to be holding — that's what makes revocation actually
// real-time: the very next lookup by id sees the new state, not a stale copy.
//
// In-memory for this walking skeleton. A real backing store (Postgres, Redis,
// whatever) would implement the same get/save shape later without touching
// any caller — that's a separate infrastructure decision, not made here.

import type { CircuitBreaker } from "./circuitBreaker.js";
import type { Token } from "./token.js";

export class TokenStore {
  #tokens = new Map<string, Token>();
  #breaker?: CircuitBreaker;

  // Optional — every existing caller that builds a TokenStore with no
  // breaker keeps working exactly as before. REQ-008 only applies where one
  // is actually wired in (server.ts).
  constructor(breaker?: CircuitBreaker) {
    this.#breaker = breaker;
  }

  save(token: Token): void {
    this.#guarded(() => this.#tokens.set(token.id, token));
  }

  get(id: string): Token | undefined {
    return this.#guarded(() => this.#tokens.get(id));
  }

  #guarded<T>(fn: () => T): T {
    return this.#breaker ? this.#breaker.execute(fn) : fn();
  }

  // Direct children only — cascadeRevoke() walks further generations itself.
  childrenOf(parentId: string): Token[] {
    return [...this.#tokens.values()].filter((t) => t.parentTokenId === parentId);
  }

  // For the console's Tokens tab — every token this process has ever issued,
  // active or revoked. Real data, not a sample: an empty store shows an
  // empty list, not a placeholder.
  list(): Token[] {
    return [...this.#tokens.values()];
  }
}
