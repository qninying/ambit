// The single source of truth for token state. enforceToken and revokeToken
// both read/write through this rather than trusting whatever Token object a
// caller happens to be holding — that's what makes revocation actually
// real-time: the very next lookup by id sees the new state, not a stale copy.
//
// ADR-014: optionally persisted to an append-only JSONL file — see
// src/jsonlStore.ts for the shared mechanics. Rehydration replays every
// save() in file order, so a later line for a given id (e.g. a revocation)
// correctly supersedes an earlier one, matching save()'s own in-memory
// last-write-wins behavior.

import type { CircuitBreaker } from "./circuitBreaker.js";
import type { Token } from "./token.js";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

function reviveToken(raw: unknown): Token {
  const t = raw as Token & { issuedAt: string; expiresAt: string; revokedAt?: string };
  return {
    ...t,
    issuedAt: new Date(t.issuedAt),
    expiresAt: new Date(t.expiresAt),
    revokedAt: t.revokedAt ? new Date(t.revokedAt) : undefined,
  };
}

export class TokenStore {
  #tokens = new Map<string, Token>();
  #breaker?: CircuitBreaker;
  #persistTo?: string;

  // Optional — every existing caller that builds a TokenStore with no
  // breaker/persistTo keeps working exactly as before. REQ-008 only applies
  // where a breaker is actually wired in (server.ts); persistTo only where
  // an operator has configured a real data directory (also server.ts).
  constructor(breaker?: CircuitBreaker, persistTo?: string) {
    this.#breaker = breaker;
    this.#persistTo = persistTo;
    if (persistTo) {
      for (const token of rehydrateJsonLines(persistTo, reviveToken)) {
        this.#tokens.set(token.id, token);
      }
    }
  }

  save(token: Token): void {
    this.#guarded(() => {
      this.#tokens.set(token.id, token);
      if (this.#persistTo) appendJsonLine(this.#persistTo, token);
    });
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
