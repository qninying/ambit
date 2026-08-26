// Real-server tests for server.ts routes that need more than the domain-
// level unit tests already cover — same real-server-on-an-ephemeral-port
// pattern sdk/ambitClient.test.ts already established, used here for the
// admin-toggle gate on /circuit-breaker/simulate-outage: a stopgap pulled
// forward ahead of ADR-009's full auth phase specifically because that
// route can disable the entire real Token & Policy Store with one
// unauthenticated request and zero prior knowledge of any real id.

import { createServer, type Server } from "node:http";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { app } from "./server.js";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  delete process.env.ADMIN_TOGGLE_KEY;
});

describe("POST /circuit-breaker/simulate-outage — admin toggle gate", () => {
  it("refuses with 403 when ADMIN_TOGGLE_KEY is not configured at all — no accidental default-open door", async () => {
    delete process.env.ADMIN_TOGGLE_KEY;
    const res = await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ down: true }),
    });
    expect(res.status).toBe(403);
  });

  it("refuses with 403 when the key is configured but the request supplies none", async () => {
    process.env.ADMIN_TOGGLE_KEY = "test-secret-1";
    const res = await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ down: true }),
    });
    expect(res.status).toBe(403);
  });

  it("refuses with 403 when the supplied key is wrong", async () => {
    process.env.ADMIN_TOGGLE_KEY = "test-secret-1";
    const res = await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ambit-admin-key": "wrong-key" },
      body: JSON.stringify({ down: true }),
    });
    expect(res.status).toBe(403);
  });

  it("succeeds and actually toggles the breaker's outage flag when the correct key is supplied", async () => {
    process.env.ADMIN_TOGGLE_KEY = "test-secret-1";
    const res = await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ambit-admin-key": "test-secret-1" },
      body: JSON.stringify({ down: true }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.down).toBe(true);

    // Undo it so this test doesn't leak a tripped/outage-simulated breaker
    // into whichever test runs next in this same module instance.
    await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ambit-admin-key": "test-secret-1" },
      body: JSON.stringify({ down: false }),
    });
  });

  // Trust: the toggle call itself must be audit-visible, distinct from the
  // breaker's own organic state-transition entries — this is the second
  // gap named alongside the missing auth (nothing recorded who touched it).
  it("logs the toggle call itself to the audit log, with an actor distinguishing it from an organic state transition", async () => {
    process.env.ADMIN_TOGGLE_KEY = "test-secret-1";
    await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ambit-admin-key": "test-secret-1" },
      body: JSON.stringify({ down: true }),
    });

    const auditRes = await fetch(`${baseUrl}/audit-log`);
    const entries: Array<Record<string, unknown>> = await auditRes.json();
    expect(entries).toContainEqual(
      expect.objectContaining({
        action: "circuit_breaker_simulate_outage",
        decision: "circuit_opened",
        actor: "admin-toggle",
      }),
    );

    // Undo it.
    await fetch(`${baseUrl}/circuit-breaker/simulate-outage`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ambit-admin-key": "test-secret-1" },
      body: JSON.stringify({ down: false }),
    });
  });
});

describe("GET /circuit-breaker — unaffected by the admin gate (read-only, intentionally left open)", () => {
  it("is reachable without any key", async () => {
    const res = await fetch(`${baseUrl}/circuit-breaker`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(["closed", "open", "half_open"]).toContain(body.state);
  });
});
