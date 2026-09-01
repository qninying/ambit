// ADR-016: rateLimiter.test.ts proves the RateLimiter class's own logic in
// isolation; this proves it's actually wired into server.ts — a real 429,
// with a real Retry-After header, over real HTTP. server.ts's module-level
// limiters read their thresholds from RATE_LIMIT_* env vars exactly once,
// at import time (a stateful limiter can't re-read its own config per
// request without losing its counts, unlike getSessionConfig()'s
// deliberately-fresh-per-request pattern) — so this file sets a
// deliberately tight limit and uses a dynamic import to defer loading
// server.ts until after that env var is set, rather than the static
// top-level import every other test file uses (which would instead pick up
// vitest.setup.ts's deliberately generous test-wide default).

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { hashPassword } from "./passwordHash.js";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  process.env.RATE_LIMIT_GENERAL_MAX_REQUESTS = "3";
  process.env.RATE_LIMIT_GENERAL_WINDOW_MS = "60000";
  const { app } = await import("./server.js");

  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  delete process.env.RATE_LIMIT_GENERAL_MAX_REQUESTS;
  delete process.env.RATE_LIMIT_GENERAL_WINDOW_MS;
});

describe("ADR-016: the general rate limiter is really wired into server.ts", () => {
  it("allows requests under the configured limit, then returns a real 429 with Retry-After", async () => {
    // Limit is 3 per window — the first 3 real requests must succeed.
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${baseUrl}/policies`);
      expect(res.status).toBe(200);
    }

    const blocked = await fetch(`${baseUrl}/policies`);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBeTruthy();
    const body = await blocked.json();
    expect(body.error).toBeTruthy();
  });
});

// A separate describe block, own server instance, own tight login-specific
// limit — proves the actual brute-force-guessing case the whole feature
// exists for: real repeated POST /auth/login attempts, real 429 once the
// (deliberately stricter) login limit is hit.
describe("ADR-016: the login rate limiter is stricter, and really wired in", () => {
  let loginServer: Server;
  let loginBaseUrl: string;

  beforeAll(async () => {
    process.env.RATE_LIMIT_GENERAL_MAX_REQUESTS = "100000"; // isolate this describe's own concern
    process.env.RATE_LIMIT_LOGIN_MAX_REQUESTS = "2";
    process.env.RATE_LIMIT_LOGIN_WINDOW_MS = "60000";
    process.env.ADMIN_USERNAME = "rate-limit-test-admin";
    process.env.ADMIN_PASSWORD_HASH = await hashPassword("rate-limit-test-password");
    process.env.SESSION_SIGNING_SECRET = "rate-limit-test-signing-secret";
    // ADR-017: login now also requires a configured TOTP secret to pass the
    // route's auth-configured gate at all — this test's attempts use a
    // deliberately wrong password anyway, so credentialsMatch short-
    // circuits before any code is ever verified (no real code needed here).
    process.env.ADMIN_TOTP_SECRET = "rate-limit-test-totp-secret";
    // Vitest's module cache would otherwise hand back the already-loaded
    // instance from the describe block above, whose limiters were already
    // constructed with different thresholds — resetModules() forces a
    // genuinely fresh evaluation of server.ts under this block's own env.
    vi.resetModules();
    const { app } = await import("./server.js");

    loginServer = createServer(app);
    await new Promise<void>((resolve) => loginServer.listen(0, resolve));
    const address = loginServer.address();
    const port = typeof address === "object" && address ? address.port : 0;
    loginBaseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => loginServer.close(() => resolve()));
    delete process.env.RATE_LIMIT_LOGIN_MAX_REQUESTS;
    delete process.env.RATE_LIMIT_LOGIN_WINDOW_MS;
    delete process.env.ADMIN_USERNAME;
    delete process.env.ADMIN_PASSWORD_HASH;
    delete process.env.SESSION_SIGNING_SECRET;
    delete process.env.ADMIN_TOTP_SECRET;
  });

  it("blocks repeated login attempts with a real 429 once the stricter login limit is hit", async () => {
    const attempt = () =>
      fetch(`${loginBaseUrl}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "guesser", password: "wrong-guess", totpCode: "000000" }),
      });

    // Limit is 2 per window — both must reach real auth logic (401, wrong
    // password), not get rate-limited themselves.
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);

    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBeTruthy();
  });
});
