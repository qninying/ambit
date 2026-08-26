// Exercises the SDK against the real, running server — not a mocked fetch —
// same standard as every other story in this build: an HTTP-shaped
// component is verified over real HTTP, in a fresh process per test file
// (vitest isolates module state per file), listening on an OS-assigned free
// port so it can't collide with a dev server or another test file.

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../src/server.js";
import { AmbitClient, AmbitClientError } from "./ambitClient.js";

let server: Server;
let client: AmbitClient;

beforeAll(async () => {
  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  client = new AmbitClient({ baseUrl: `http://127.0.0.1:${port}`, timeoutMs: 1_000, retryDelayMs: 5 });
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("AmbitClient.requestToken", () => {
  // Given a developer, when they use the SDK, then they can request a token.
  it("submits a real request to the real server and gets a pending request back", async () => {
    const request = await client.requestToken({ subject: "sdk-agent-1", scope: ["email:send"], ttlSeconds: 300 });

    expect(request.id).toBeTruthy();
    expect(request.status).toBe("pending");
    expect(request.subject).toBe("sdk-agent-1");
  });

  // Given a token request, when it is invalid, then an error is returned —
  // not a generic HTTP failure the caller has to decode themselves.
  it("throws a typed AmbitClientError with the server's own message for an invalid request", async () => {
    await expect(
      // @ts-expect-error — deliberately missing scope, the failure path under test
      client.requestToken({ subject: "sdk-agent-1", ttlSeconds: 300 }),
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
        client.requestToken({ subject: "sdk-agent-1", ttlSeconds: 300, idempotencyKey: "bad-request-key" }),
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
      subject: "sdk-agent-2",
      scope: ["email:send"],
      ttlSeconds: 300,
      idempotencyKey: "sdk-retry-key-1",
    });
    const second = await client.requestToken({
      subject: "sdk-agent-2",
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
        subject: "sdk-agent-retry",
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
    const shortTimeoutClient = new AmbitClient({ baseUrl: "http://127.0.0.1:1", timeoutMs: 50, maxAttempts: 1 });
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
        shortTimeoutClient.requestToken({ subject: "sdk-agent-timeout", scope: ["email:send"], ttlSeconds: 300 }),
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
    const submitted = await client.requestToken({ subject: "sdk-agent-3", scope: ["email:send"], ttlSeconds: 300 });

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
