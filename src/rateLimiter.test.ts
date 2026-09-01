import { describe, it, expect } from "vitest";
import { RateLimiter } from "./rateLimiter.js";

describe("RateLimiter", () => {
  it("allows requests under the limit", () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 3 });
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(true);
  });

  it("allows exactly maxRequests, then blocks the next one", () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 3 });
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(true);
    const blocked = limiter.check("a");
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterMs).toBeGreaterThan(0);
  });

  it("reports a retryAfterMs bounded by the window size", () => {
    let now = 1_000_000;
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1, now: () => now });
    limiter.check("a");
    const blocked = limiter.check("a");
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterMs).toBeLessThanOrEqual(60_000);
    expect(blocked.retryAfterMs).toBeGreaterThan(0);
  });

  it("resets after the window elapses (injectable clock)", () => {
    let now = 1_000_000;
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1, now: () => now });
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(false);
    now += 60_000;
    expect(limiter.check("a").allowed).toBe(true);
  });

  it("does not reset a moment before the window elapses", () => {
    let now = 1_000_000;
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1, now: () => now });
    expect(limiter.check("a").allowed).toBe(true);
    now += 59_999;
    expect(limiter.check("a").allowed).toBe(false);
  });

  it("tracks independent keys separately", () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1 });
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(false);
    expect(limiter.check("b").allowed).toBe(true);
  });
});
