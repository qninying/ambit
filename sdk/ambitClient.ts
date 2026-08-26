// REQ-014: a client SDK for developers to request and present tokens. Lives
// outside src/ deliberately — src/ is Ambit's own server-side domain logic;
// this is the thing an external developer imports to talk to a *running*
// Ambit server over HTTP. Same TypeScript project (see ADR-008's sibling
// note in PROGRESS.md for why a second real npm package wasn't worth it at
// this stage), but a structurally separate directory so the boundary reads
// as intentional, not accidental.

export interface AmbitClientConfig {
  // Base URL of a running Ambit server, e.g. "http://localhost:4000".
  baseUrl: string;
  timeoutMs?: number;
  maxAttempts?: number;
  retryDelayMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 100;

// Never swallowed — every non-2xx or network/timeout failure surfaces as
// this, carrying the server's own error message when there was one, and a
// status of 0 for a failure that never got as far as an HTTP response
// (timeout, connection refused) so callers can tell the two apart.
export class AmbitClientError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "AmbitClientError";
  }
}

export interface RequestTokenParams {
  subject: string;
  scope: string[];
  ttlSeconds: number;
  policyId?: string;
  // Optional. Supply one to make this call safe for the client's own
  // timeout-and-retry loop to repeat — see requestToken() below for exactly
  // what "safe" means here.
  idempotencyKey?: string;
}

export interface RemoteRequest {
  id: string;
  subject: string;
  scope: string[];
  ttlSeconds: number;
  status: "pending" | "approved" | "denied";
  requestedAt: string;
  tokenId?: string;
  policyId?: string;
  idempotencyKey?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AmbitClient {
  #baseUrl: string;
  #timeoutMs: number;
  #maxAttempts: number;
  #retryDelayMs: number;

  constructor(config: AmbitClientConfig) {
    this.#baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.#timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#retryDelayMs = config.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  }

  // Given a developer, when they use the SDK, then they can request a
  // token — this is that call. Retries (capped, per CLAUDE.md) only happen
  // when the caller supplied an idempotencyKey: without one, a retry after
  // a lost response could create a second pending request, so this method
  // makes exactly one attempt in that case rather than guess.
  async requestToken(params: RequestTokenParams): Promise<RemoteRequest> {
    const attempts = params.idempotencyKey ? this.#maxAttempts : 1;
    return this.#send("POST", "/requests", params, attempts);
  }

  // The other half of "request and present tokens" — once a request stops
  // being pending, this is how the SDK finds out what happened to it, and
  // (once approved) the tokenId to present. Idempotent by nature (a GET),
  // so always safe to retry up to the configured cap.
  async getRequest(id: string): Promise<RemoteRequest> {
    return this.#send("GET", `/requests/${encodeURIComponent(id)}`, undefined, this.#maxAttempts);
  }

  async #send(method: string, path: string, body: unknown, maxAttempts: number): Promise<any> {
    let lastError: AmbitClientError | undefined;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
      try {
        const response = await fetch(`${this.#baseUrl}${path}`, {
          method,
          headers: body !== undefined ? { "content-type": "application/json" } : undefined,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => undefined);

        if (!response.ok) {
          // A 4xx is the server telling us the request itself is invalid —
          // retrying an unchanged request would just fail the same way, so
          // this is a genuine failure, not a candidate for retry.
          throw new AmbitClientError(
            payload?.error ?? `${method} ${path} failed with status ${response.status}`,
            response.status,
          );
        }
        return payload;
      } catch (err) {
        lastError =
          err instanceof AmbitClientError
            ? err
            : err instanceof Error && err.name === "AbortError"
              ? new AmbitClientError(`${method} ${path} timed out after ${this.#timeoutMs}ms`, 0)
              : new AmbitClientError(`${method} ${path} failed: ${(err as Error).message}`, 0);

        // Only retry the failure classes a retry can plausibly fix (timeout,
        // connection failure, 5xx) — never a 4xx, which a retry can't change.
        const retryable = lastError.status === 0 || lastError.status >= 500;
        if (!retryable || attempt >= maxAttempts) throw lastError;
        await sleep(this.#retryDelayMs);
      } finally {
        clearTimeout(timer);
      }
    }

    // Unreachable in practice (the loop always returns or throws), but keeps
    // the function's return type honest without a non-null assertion.
    throw lastError ?? new AmbitClientError(`${method} ${path} failed`, 0);
  }
}
