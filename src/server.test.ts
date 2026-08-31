// Real-server tests for server.ts routes that need more than the domain-
// level unit tests already cover — same real-server-on-an-ephemeral-port
// pattern sdk/ambitClient.test.ts already established, used here for the
// admin-toggle gate on /circuit-breaker/simulate-outage: a stopgap pulled
// forward ahead of ADR-009's full auth phase specifically because that
// route can disable the entire real Token & Policy Store with one
// unauthenticated request and zero prior knowledge of any real id.

import { createServer, type Server } from "node:http";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { hashPassword } from "./passwordHash.js";
import { app } from "./server.js";

let server: Server;
let baseUrl: string;

const TEST_ADMIN_USERNAME = "test-admin";
const TEST_ADMIN_PASSWORD = "correct horse battery staple";
const TEST_SESSION_SECRET = "test-session-signing-secret-do-not-use-in-prod";

beforeAll(async () => {
  // Auth config is read fresh per-request in server.ts specifically so
  // tests can configure it here, after import, rather than needing a
  // separate module instance per configuration.
  process.env.ADMIN_USERNAME = TEST_ADMIN_USERNAME;
  process.env.ADMIN_PASSWORD_HASH = await hashPassword(TEST_ADMIN_PASSWORD);
  process.env.SESSION_SIGNING_SECRET = TEST_SESSION_SECRET;

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

// Real login, real session token — every test that needs to approve/deny
// gets one of these rather than a hand-rolled fake, so this suite exercises
// the actual auth flow, not a bypass of it.
async function login(): Promise<string> {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: TEST_ADMIN_USERNAME, password: TEST_ADMIN_PASSWORD }),
  });
  const body = await res.json();
  return body.token;
}

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

// REQ-009 hardening: found and fixed during this story's own post-story
// review. A caller must never be able to pick which redaction rule grades
// their own access request — that would let anyone with an unauthenticated
// POST to /redaction-rules create a trivially weak rule and select it,
// bypassing redaction regardless of caller auth. The route ignores
// redactionRuleId entirely; this proves it, over real HTTP.
describe("POST /tokens/:id/customer-data/:customerId — ignores a caller-supplied redactionRuleId", () => {
  async function issueTestToken(scope: string[]): Promise<string> {
    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "server-test-agent", scope, ttlSeconds: 300 }),
    });
    const { id: requestId } = await reqRes.json();
    const sessionToken = await login();
    const approveRes = await fetch(`${baseUrl}/requests/${requestId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({}),
    });
    const token = await approveRes.json();
    return token.id;
  }

  it("still redacts ssn even when the request body supplies a rule id crafted to require only baseline scope", async () => {
    // A malicious/naive rule requiring only "customer:read" — the SAME
    // scope already needed for baseline access — for ssn. If the route
    // honored this, a plain customer:read token would see ssn unredacted.
    const weakRuleRes = await fetch(`${baseUrl}/redaction-rules`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Deliberately weak", sensitiveFields: { ssn: "customer:read" }, authoredBy: "test" }),
    });
    const weakRule = await weakRuleRes.json();

    const tokenId = await issueTestToken(["customer:read"]);
    const res = await fetch(`${baseUrl}/tokens/${tokenId}/customer-data/cust-001`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redactionRuleId: weakRule.id }),
    });
    const result = await res.json();

    expect(result.allowed).toBe(true);
    expect(result.data.ssn).toBe("[REDACTED]"); // the weak rule was never applied
  });
});

// ADR-010: found during a full trust-boundary audit after all 12 stories
// shipped. A requester citing their own policyId at submission time made
// "policy attached" a self-issued rubber stamp — anyone could create a
// maximally permissive policy and cite it on their own request, and the
// approver had no way to see which policy (if any) was really attached
// before clicking Approve. Fixed by moving policy selection to approval
// time; this proves it over real HTTP.
describe("Policy selection is the approver's choice, not the requester's", () => {
  it("ignores a policyId supplied at submission time entirely", async () => {
    // A deliberately permissive policy an attacker might create and cite
    // on their own request, hoping approveRequest would inherit it.
    const permissiveRes = await fetch(`${baseUrl}/policies`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Attacker-authored", allowedScope: ["payment:charge"], maxTtlSeconds: 999999, authoredBy: "attacker" }),
    });
    const permissivePolicy = await permissiveRes.json();

    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "policy-test-agent", scope: ["email:send"], ttlSeconds: 300, policyId: permissivePolicy.id }),
    });
    const pending = await reqRes.json();
    // The route silently ignores an unrecognized field — proves the
    // submitted request never carries a policyId at all, not just that
    // it's later overridden.
    expect(pending.policyId).toBeUndefined();

    // Approve with NO policyId — if the server had inherited the
    // requester's submitted one, this approval would be checked against
    // the attacker's permissive policy instead of going through unchecked.
    const sessionToken = await login();
    const approveRes = await fetch(`${baseUrl}/requests/${pending.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({}),
    });
    expect(approveRes.status).toBe(200);
  });

  it("actually enforces the policy the approver picks at approval time", async () => {
    const restrictiveRes = await fetch(`${baseUrl}/policies`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Email only, approver-chosen", allowedScope: ["email:send"], maxTtlSeconds: 3600, authoredBy: "privacy-officer" }),
    });
    const restrictivePolicy = await restrictiveRes.json();

    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "policy-test-agent-2", scope: ["payment:charge"], ttlSeconds: 300 }),
    });
    const pending = await reqRes.json();

    // The approver attaches a real, restrictive policy at approval time —
    // this request's scope (payment:charge) exceeds it, so it must fail.
    const sessionToken = await login();
    const approveRes = await fetch(`${baseUrl}/requests/${pending.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({ policyId: restrictivePolicy.id }),
    });
    expect(approveRes.status).toBe(400); // PolicyViolationError, caught by the generic error middleware
    const body = await approveRes.json();
    expect(body.error).toContain(restrictivePolicy.name);

    const stillPending = await fetch(`${baseUrl}/requests/${pending.id}`).then((r) => r.json());
    expect(stillPending.status).toBe("pending"); // denied by policy, not consumed — a corrected retry stays possible
  });
});

// ADR-009 hardening: real operator authentication. Verified over real HTTP
// against the actual login endpoint and the actual session gate — not
// against the underlying primitives in isolation (those already have their
// own unit tests in sessionToken.test.ts/passwordHash.test.ts).
describe("POST /auth/login and requireSession", () => {
  it("issues a real session token for the correct username and password", async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: TEST_ADMIN_USERNAME, password: TEST_ADMIN_PASSWORD }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body.token).toBe("string");
  });

  it("refuses login with the wrong password, and logs the attempt", async () => {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: TEST_ADMIN_USERNAME, password: "wrong-password" }),
    });
    expect(res.status).toBe(401);

    const entries: Array<Record<string, unknown>> = await fetch(`${baseUrl}/audit-log`).then((r) => r.json());
    expect(entries).toContainEqual(
      expect.objectContaining({ action: "login", decision: "denied", reasonCode: "invalid_credentials", subject: TEST_ADMIN_USERNAME }),
    );
  });

  it("refuses login when auth is not configured at all, rather than defaulting open", async () => {
    const original = process.env.SESSION_SIGNING_SECRET;
    delete process.env.SESSION_SIGNING_SECRET;
    try {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: TEST_ADMIN_USERNAME, password: TEST_ADMIN_PASSWORD }),
      });
      expect(res.status).toBe(503);
    } finally {
      process.env.SESSION_SIGNING_SECRET = original;
    }
  });

  it("refuses to approve a request with no session at all", async () => {
    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "auth-test-agent", scope: ["email:send"], ttlSeconds: 300 }),
    });
    const pending = await reqRes.json();

    const approveRes = await fetch(`${baseUrl}/requests/${pending.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(approveRes.status).toBe(401);
  });

  it("refuses to approve a request with a tampered/invalid session token", async () => {
    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "auth-test-agent-2", scope: ["email:send"], ttlSeconds: 300 }),
    });
    const pending = await reqRes.json();

    const approveRes = await fetch(`${baseUrl}/requests/${pending.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer not-a-real-session-token" },
      body: JSON.stringify({}),
    });
    expect(approveRes.status).toBe(401);
  });

  // The actual point of this whole change: approver is the real,
  // authenticated identity — never something the client could just type in.
  it("derives the audit trail's approver from the real session, ignoring any approver the client sends", async () => {
    const reqRes = await fetch(`${baseUrl}/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: "auth-test-agent-3", scope: ["email:send"], ttlSeconds: 300 }),
    });
    const pending = await reqRes.json();
    const sessionToken = await login();

    await fetch(`${baseUrl}/requests/${pending.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
      // A malicious or confused client trying to claim a different identity —
      // must be ignored entirely.
      body: JSON.stringify({ approver: "someone-else-entirely" }),
    });

    const entries: Array<Record<string, unknown>> = await fetch(`${baseUrl}/audit-log`).then((r) => r.json());
    expect(entries).toContainEqual(
      expect.objectContaining({ requestId: pending.id, decision: "request_approved", actor: TEST_ADMIN_USERNAME }),
    );
    expect(entries.some((e) => e.actor === "someone-else-entirely")).toBe(false);
  });
});
