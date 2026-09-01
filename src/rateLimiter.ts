// Fixed-window rate limiter, in-memory, per key. Closes a real gap the
// INPACT trust-scorecard assessment surfaced: grepping this repo for rate
// limiting turned up nothing — POST /auth/login accepted unlimited password
// guesses, and no route had any flood protection at all. Ported from
// CoreOps's own rateLimiter.ts (same problem, same right-sized answer),
// not reinvented.
//
// Fixed window (not sliding/token-bucket) is deliberate: Ambit is a
// single-operator portfolio demo, not a public API under adversarial
// load-shaping pressure. A fixed window's boundary-burst behavior (up to 2x
// the limit across a window edge) is an acceptable tradeoff for the actual
// threat model here — a scripted brute-force loop, not an attacker
// specifically evading rate-limit windows.

export interface RateLimiterOptions {
  windowMs: number;
  maxRequests: number;
  now?: () => number;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs: number;
}

interface WindowState {
  count: number;
  windowStartedAt: number;
}

export class RateLimiter {
  #windowMs: number;
  #maxRequests: number;
  #now: () => number;
  #windows = new Map<string, WindowState>();

  constructor(options: RateLimiterOptions) {
    this.#windowMs = options.windowMs;
    this.#maxRequests = options.maxRequests;
    this.#now = options.now ?? (() => Date.now());
  }

  check(key: string): RateLimitResult {
    const nowMs = this.#now();
    const existing = this.#windows.get(key);

    if (!existing || nowMs - existing.windowStartedAt >= this.#windowMs) {
      this.#windows.set(key, { count: 1, windowStartedAt: nowMs });
      return { allowed: true, retryAfterMs: 0 };
    }

    if (existing.count < this.#maxRequests) {
      existing.count += 1;
      return { allowed: true, retryAfterMs: 0 };
    }

    const retryAfterMs = existing.windowStartedAt + this.#windowMs - nowMs;
    return { allowed: false, retryAfterMs };
  }
}
