// The single source of truth for token state. enforceToken and revokeToken
// both read/write through this rather than trusting whatever Token object a
// caller happens to be holding — that's what makes revocation actually
// real-time: the very next lookup by id sees the new state, not a stale copy.
//
// In-memory for this walking skeleton. A real backing store (Postgres, Redis,
// whatever) would implement the same get/save shape later without touching
// any caller — that's a separate infrastructure decision, not made here.

import type { Token } from "./token.js";

export class TokenStore {
  #tokens = new Map<string, Token>();

  save(token: Token): void {
    this.#tokens.set(token.id, token);
  }

  get(id: string): Token | undefined {
    return this.#tokens.get(id);
  }
}
