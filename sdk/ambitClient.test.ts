// Exercises the SDK against the real, running server — not a mocked fetch —
// same standard as every other story in this build: an HTTP-shaped
// component is verified over real HTTP, in a fresh process per test file
// (vitest isolates module state per file), listening on an OS-assigned free
// port so it can't collide with a dev server or another test file.

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hashPassword } from "../src/passwordHash.js";
import { app } from "../src/server.js";
import { generateTotpCode, generateTotpSecret } from "../src/totp.js";
import { AmbitClient, AmbitClientError } from "./ambitClient.js";

let server: Server;
let client: AmbitClient;
let baseUrl: string;
let adminSessionToken: string;
const SDK_TEST_SUBJECT = "sdk-test-agent";

beforeAll(async () => {
  process.env.ADMIN_USERNAME = "sdk-test-admin";
  process.env.ADMIN_PASSWORD_HASH = await hashPassword("sdk-test-password");
  process.env.SESSION_SIGNING_SECRET = "sdk-test-signing-secret";
  const totpSecret = generateTotpSecret();
  process.env.ADMIN_TOTP_SECRET = totpSecret;

  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;

  // ADR-009 hardening: requestToken() now needs a real, pre-registered
  // agent credential — same as any real caller would, not a bypass. An
  // operator logs in, registers the agent this SDK instance speaks for,
  // and the client is configured with the resulting credential. This is
  // the only login this file performs, so there's no ADR-017 replay
  // collision to worry about (unlike server.test.ts, which logs in many
  // times and had to memoize).
  const loginRes = await fetch(`${baseUrl}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "sdk-test-admin", password: "sdk-test-password", totpCode: generateTotpCode(totpSecret, Date.now()) }),
  });
  const { token: sessionToken } = await loginRes.json();
  adminSessionToken = sessionToken;
  const registerRes = await fetch(`${baseUrl}/agent-identities`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({ subject: SDK_TEST_SUBJECT }),
  });
  const { credential } = await registerRes.json();

  client = new AmbitClient({ baseUrl, agentCredential: credential, timeoutMs: 1_000, retryDelayMs: 5 });
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("AmbitClient.requestToken", () => {
  // ADR-009 hardening: fails fast, client-side, with an actionable message
  // — never even reaches the network — rather than surfacing a bare 401
  // the caller has to reverse-engineer.
  it("refuses to call requestToken at all when no agentCredential is configured", async () => {
    const noCredClient = new AmbitClient({ baseUrl });
    await expect(noCredClient.requestToken({ scope: ["email:send"], ttlSeconds: 300 })).rejects.toMatchObject({
      name: "AmbitClientError",
      message: expect.stringContaining("agentCredential"),
    });
  });

  // Given a developer, when they use the SDK, then they can request a token.
  it("submits a real request to the real server and gets a pending request back", async () => {
    const request = await client.requestToken({ scope: ["email:send"], ttlSeconds: 300 });

    expect(request.id).toBeTruthy();
    expect(request.status).toBe("pending");
    // Derived from the registered agent credential, not something this
    // call specified — proving subject really is server-derived, not just
    // absent from the type.
    expect(request.subject).toBe(SDK_TEST_SUBJECT);
  });

  // Given a token request, when it is invalid, then an error is returned —
  // not a generic HTTP failure the caller has to decode themselves.
  it("throws a typed AmbitClientError with the server's own message for an invalid request", async () => {
    await expect(
      // @ts-expect-error — deliberately missing scope, the failure path under test
      client.requestToken({ ttlSeconds: 300 }),
    ).rejects.toMatchObject({
      name: "AmbitClientError",
      status: 400,
    });
  });

  // Even with an idempotencyKey (which raises the attempt budget above 1),
  // a 400 must not be retried — a retry can't fix a request the server has
  // already judged malformed.
  it("does not retry a 400, even when an idempotencyKey makes retries otherwise available", async () => {
    let calls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
      calls++;
      return originalFetch(...args);
    }) as typeof fetch;

    try {
      await expect(
        // @ts-expect-error — deliberately missing scope, the failure path under test
        client.requestToken({ ttlSeconds: 300, idempotencyKey: "bad-request-key" }),
      ).rejects.toThrow(AmbitClientError);
      expect(calls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // The idempotency contract: retried with the same key, the SDK-and-server
  // pair together produce exactly one request, not two.
  it("submitting the same idempotencyKey twice returns the same request rather than creating a second one", async () => {
    const first = await client.requestToken({
      scope: ["email:send"],
      ttlSeconds: 300,
      idempotencyKey: "sdk-retry-key-1",
    });
    const second = await client.requestToken({
      scope: ["email:send"],
      ttlSeconds: 300,
      idempotencyKey: "sdk-retry-key-1",
    });

    expect(second.id).toBe(first.id);
  });
});

describe("AmbitClient reliability (CLAUDE.md: explicit timeout, capped retries)", () => {
  // Proves the retry loop actually recovers from a transient failure, not
  // just that it's declared — same standard mockEndpointAccess.test.ts sets
  // for the mock-endpoint retry wrapper.
  it("retries a request bearing an idempotencyKey after a transient 500 and succeeds on the next attempt", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
      calls++;
      if (calls === 1) return new Response(JSON.stringify({ error: "transient" }), { status: 500 });
      return originalFetch(...args);
    }) as typeof fetch;

    try {
      const result = await client.requestToken({
        scope: ["email:send"],
        ttlSeconds: 300,
        idempotencyKey: "sdk-retry-key-transient",
      });
      expect(calls).toBe(2);
      expect(result.status).toBe("pending");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // A hung connection must not wait forever — it fails within the
  // configured timeout, reported as a status:0 AmbitClientError (never
  // reached a real HTTP response) rather than left unbounded.
  it("times out a request that never responds, instead of hanging indefinitely", async () => {
    // agentCredential doesn't need to be real here — fetch itself is
    // mocked below, and this is only present so the client's own
    // "credential configured?" check doesn't short-circuit before the
    // timeout behavior under test ever gets exercised.
    const shortTimeoutClient = new AmbitClient({ baseUrl: "http://127.0.0.1:1", agentCredential: "fake.fake", timeoutMs: 50, maxAttempts: 1 });
    const originalFetch = globalThis.fetch;
    // A real hung connection settles (rejects) once its AbortSignal fires —
    // this mock has to do the same, or the abort() below has nothing to
    // reject and the test (and the client's own await) hangs for real.
    globalThis.fetch = ((_url: string, opts?: RequestInit) =>
      new Promise((_resolve, reject) => {
        opts?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      })) as typeof fetch;

    try {
      await expect(
        shortTimeoutClient.requestToken({ scope: ["email:send"], ttlSeconds: 300 }),
      ).rejects.toMatchObject({ name: "AmbitClientError", status: 0 });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("AmbitClient.getRequest", () => {
  // Trust: SDK usage is logged — verified here by checking the real
  // consequence (the request exists server-side and can be read back with
  // its real status), not by asserting against the SDK's own internals.
  it("reads back the real status of a request submitted through the SDK", async () => {
    const submitted = await client.requestToken({ scope: ["email:send"], ttlSeconds: 300 });

    const fetched = await client.getRequest(submitted.id);

    expect(fetched).toEqual(submitted);
  });

  it("throws a 404 AmbitClientError for a request id that doesn't exist", async () => {
    await expect(client.getRequest("not-a-real-id")).rejects.toMatchObject({
      name: "AmbitClientError",
      status: 404,
    });
  });
});

// ADR-013: the real end-to-end flow — request, approve (as the operator,
// outside the SDK's own concern), claim, then a secret that genuinely
// authenticates against the real token it belongs to.
describe("AmbitClient.claimTokenSecret", () => {
  async function approve(requestId: string): Promise<void> {
    await fetch(`${baseUrl}/requests/${requestId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${adminSessionToken}` },
      body: JSON.stringify({}),
    });
  }

  it("claims a secret that genuinely enforces against the real token, exactly once", async () => {
    const submitted = await client.requestToken({ scope: ["email:send"], ttlSeconds: 300 });
    await approve(submitted.id);

    const claimed = await client.claimTokenSecret(submitted.id);
    expect(claimed.tokenId).toBeTruthy();

    const enforceRes = await fetch(`${baseUrl}/tokens/${claimed.tokenId}/enforce`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${claimed.secret}` },
      body: JSON.stringify({ action: "email:send" }),
    });
    expect(await enforceRes.json()).toEqual({ allowed: true });

    // The one-time guarantee, from the SDK's own vantage point.
    await expect(client.claimTokenSecret(submitted.id)).rejects.toMatchObject({
      name: "AmbitClientError",
      status: 410,
    });
  });

  it("throws a 409 AmbitClientError when the request has not been approved yet", async () => {
    const submitted = await client.requestToken({ scope: ["email:send"], ttlSeconds: 300 });

    await expect(client.claimTokenSecret(submitted.id)).rejects.toMatchObject({
      name: "AmbitClientError",
      status: 409,
    });
  });

  it("refuses to call claimTokenSecret at all when no agentCredential is configured", async () => {
    const noCredClient = new AmbitClient({ baseUrl });
    await expect(noCredClient.claimTokenSecret("irrelevant-id")).rejects.toMatchObject({
      name: "AmbitClientError",
      status: 0,
    });
  });
});
