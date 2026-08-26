// REQ-006/REQ-007: reach a mock endpoint only through the Enforcement Gateway
// — a token that can't be confirmed valid never gets as far as attempting the
// call. This is the first genuinely external-shaped call in the build, so
// the CLAUDE.md rule ("every external call gets an explicit timeout and
// capped retries") applies for real here, not just in principle.
//
// Timeout/retry numbers are a judgment call, same as the anomaly detector's
// thresholds — configurable here and via env vars in server.ts, not
// hardcoded, so a wrong guess (or a test that needs a fast timeout) doesn't
// require a code change.

import type { AuditLog } from "./auditLog.js";
import { enforceToken } from "./token.js";
import type { TokenStore } from "./tokenStore.js";
import { EndpointUnreachableError, type MockEndpointRegistry, type MockEndpointResult, type MockSystem } from "./mockEndpoints.js";

export interface MockEndpointAccessConfig {
  timeoutMs: number;
  maxAttempts: number;
  retryDelayMs: number;
}

export const DEFAULT_MOCK_ENDPOINT_ACCESS_CONFIG: MockEndpointAccessConfig = {
  timeoutMs: 2_000,
  maxAttempts: 2,
  retryDelayMs: 20,
};

export type AccessResult =
  | { allowed: true; outcome: "success"; result: MockEndpointResult }
  | { allowed: true; outcome: "unreachable" }
  | { allowed: false; reasonCode: string };

function withTimeout<T>(promise: Promise<T>, ms: number, system: MockSystem): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new EndpointUnreachableError(system)), ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function accessMockEndpoint(
  tokenId: string,
  system: MockSystem,
  verb: string,
  tokenStore: TokenStore,
  auditLog: AuditLog,
  registry: MockEndpointRegistry,
  config: Partial<MockEndpointAccessConfig> = {},
  now: Date = new Date(),
): Promise<AccessResult> {
  const cfg: MockEndpointAccessConfig = {
    timeoutMs: config.timeoutMs ?? DEFAULT_MOCK_ENDPOINT_ACCESS_CONFIG.timeoutMs,
    maxAttempts: config.maxAttempts ?? DEFAULT_MOCK_ENDPOINT_ACCESS_CONFIG.maxAttempts,
    retryDelayMs: config.retryDelayMs ?? DEFAULT_MOCK_ENDPOINT_ACCESS_CONFIG.retryDelayMs,
  };

  const action = `${system}:${verb}`;
  const decision = enforceToken(tokenId, action, tokenStore, auditLog, now);
  if (!decision.allowed) {
    return { allowed: false, reasonCode: decision.reasonCode };
  }

  const token = tokenStore.get(tokenId);
  // enforceToken only returns allowed:true when it found the token, so this
  // is always defined here — narrowed for TypeScript, not a real branch.
  const subject = token ? token.subject : "unknown";

  let lastError: unknown;
  for (let attempt = 1; attempt <= cfg.maxAttempts; attempt++) {
    try {
      const result = await withTimeout(registry.call(system, verb), cfg.timeoutMs, system);
      auditLog.record({ tokenId, subject, action, decision: "allowed", outcome: "success" }, now);
      return { allowed: true, outcome: "success", result };
    } catch (err) {
      lastError = err;
      if (attempt < cfg.maxAttempts) await sleep(cfg.retryDelayMs);
    }
  }

  if (!(lastError instanceof EndpointUnreachableError)) {
    throw lastError; // never swallow an error that isn't the one we're prepared to handle
  }
  auditLog.record({ tokenId, subject, action, decision: "allowed", outcome: "unreachable" }, now);
  return { allowed: true, outcome: "unreachable" };
}
