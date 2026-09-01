// ADR-017: totp.test.ts proves the TotpVerifier class's own logic in
// isolation; this proves it's actually wired into POST /auth/login — real
// HTTP, a real 400/401/503/200, against a real server. Own instance, own
// vi.resetModules() + dynamic import, own ADMIN_TOTP_SECRET — same
// "stateful singleton needs a clean instance per scenario" reasoning
// rateLimitWiring.test.ts's second describe block already established.
// server.test.ts's shared server proves the happy path and the wrong-
// password path already (see login()'s own comment there for why); these
// TOTP-specific edge cases — missing code, wrong code, a genuine replay —
// need a TotpVerifier nothing else has touched yet, so they get their own
// server rather than risking a collision with a code another test already
// consumed.

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { hashPassword } from "./passwordHash.js";
import { generateTotpCode, generateTotpSecret } from "./totp.js";

let server: Server;
let baseUrl: string;

const USERNAME = "totp-wiring-test-admin";
const PASSWORD = "totp-wiring-test-password";
const TOTP_SECRET = generateTotpSecret();

function currentCode(): string {
  return generateTotpCode(TOTP_SECRET, Date.now());
}

beforeAll(async () => {
  process.env.ADMIN_USERNAME = USERNAME;
  process.env.ADMIN_PASSWORD_HASH = await hashPassword(PASSWORD);
  process.env.SESSION_SIGNING_SECRET = "totp-wiring-test-signing-secret";
  process.env.ADMIN_TOTP_SECRET = TOTP_SECRET;
  vi.resetModules();
  const { app } = await import("./server.js");

  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  delete process.env.ADMIN_USERNAME;
  delete process.env.ADMIN_PASSWORD_HASH;
  delete process.env.SESSION_SIGNING_SECRET;
  delete process.env.ADMIN_TOTP_SECRET;
});

describe("ADR-017: TOTP MFA is really wired into POST /auth/login", () => {
  it("rejects a login missing totpCode with a 400, not a silent bypass", async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects the right username/password with a wrong TOTP code — the same generic 401 a wrong password gets", async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password: PASSWORD, totpCode: "000000" }),
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("invalid username, password, or authentication code");
  });

  it("fails closed with a 503 if ADMIN_TOTP_SECRET specifically is unset, same treatment SESSION_SIGNING_SECRET already gets", async () => {
    const original = process.env.ADMIN_TOTP_SECRET;
    delete process.env.ADMIN_TOTP_SECRET;
    try {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: USERNAME, password: PASSWORD, totpCode: currentCode() }),
      });
      expect(res.status).toBe(503);
    } finally {
      process.env.ADMIN_TOTP_SECRET = original;
    }
  });

  it("accepts a genuinely correct code once, then rejects an immediate replay of the exact same code", async () => {
    const code = currentCode();

    const first = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password: PASSWORD, totpCode: code }),
    });
    expect(first.status).toBe(200);
    const { token } = await first.json();
    expect(typeof token).toBe("string");

    const replay = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password: PASSWORD, totpCode: code }),
    });
    expect(replay.status).toBe(401);
  });
});
