// ADR-019: tokenRequest.test.ts and operatorDirectory.test.ts already prove
// the assignment/escalation logic and the two-identity login match in
// isolation; this proves both are *actually wired into* server.ts over real
// HTTP — a second real login, a real 403 from the wrong decider, and a real
// escalation once REQUEST_DECISION_WINDOW_MS elapses. Own server instance
// (vi.resetModules() + dynamic import), same pattern rateLimitWiring.test.ts
// and totpLoginWiring.test.ts already established, since this file needs
// its own tight REQUEST_DECISION_WINDOW_MS that no other test file shares.

import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { hashPassword } from "./passwordHash.js";
import { generateTotpCode, generateTotpSecret } from "./totp.js";

let server: Server;
let baseUrl: string;
// Memoized after one real login each — a real TOTP code can only be
// verified once per 30-second step (ADR-017's replay protection is real),
// so calling login() fresh in every test would collide the same way
// server.test.ts's own login() helper had to guard against.
let primaryToken: string;
let backupToken: string;

const PRIMARY_USERNAME = "accountability-primary";
const PRIMARY_PASSWORD = "primary-password";
const PRIMARY_TOTP_SECRET = generateTotpSecret();
const BACKUP_USERNAME = "accountability-backup";
const BACKUP_PASSWORD = "backup-password";
const BACKUP_TOTP_SECRET = generateTotpSecret();

async function login(username: string, password: string, totpSecret: string): Promise<string> {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password, totpCode: generateTotpCode(totpSecret, Date.now()) }),
  });
  const body = await res.json();
  return body.token;
}

beforeAll(async () => {
  process.env.ADMIN_USERNAME = PRIMARY_USERNAME;
  process.env.ADMIN_PASSWORD_HASH = await hashPassword(PRIMARY_PASSWORD);
  process.env.ADMIN_TOTP_SECRET = PRIMARY_TOTP_SECRET;
  process.env.BACKUP_APPROVER_USERNAME = BACKUP_USERNAME;
  process.env.BACKUP_APPROVER_PASSWORD_HASH = await hashPassword(BACKUP_PASSWORD);
  process.env.BACKUP_APPROVER_TOTP_SECRET = BACKUP_TOTP_SECRET;
  process.env.SESSION_SIGNING_SECRET = "accountability-wiring-test-signing-secret";
  process.env.REQUEST_DECISION_WINDOW_MS = "150";
  vi.resetModules();
  const { app } = await import("./server.js");

  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;

  // One real login per identity for the whole file — see the module-level
  // comment on primaryToken/backupToken for why these aren't re-fetched per
  // test.
  primaryToken = await login(PRIMARY_USERNAME, PRIMARY_PASSWORD, PRIMARY_TOTP_SECRET);
  backupToken = await login(BACKUP_USERNAME, BACKUP_PASSWORD, BACKUP_TOTP_SECRET);
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  delete process.env.ADMIN_USERNAME;
  delete process.env.ADMIN_PASSWORD_HASH;
  delete process.env.ADMIN_TOTP_SECRET;
  delete process.env.BACKUP_APPROVER_USERNAME;
  delete process.env.BACKUP_APPROVER_PASSWORD_HASH;
  delete process.env.BACKUP_APPROVER_TOTP_SECRET;
  delete process.env.SESSION_SIGNING_SECRET;
  delete process.env.REQUEST_DECISION_WINDOW_MS;
});

async function submitRequest(primaryToken: string, subject: string): Promise<string> {
  const registerRes = await fetch(`${baseUrl}/agent-identities`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${primaryToken}` },
    body: JSON.stringify({ subject }),
  });
  const { credential } = await registerRes.json();
  const requestRes = await fetch(`${baseUrl}/requests`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${credential}` },
    body: JSON.stringify({ scope: ["email:send"], ttlSeconds: 300 }),
  });
  const pending = await requestRes.json();
  return pending.id;
}

describe("ADR-019: a real second approver identity is really wired into POST /auth/login", () => {
  it("the backup identity really logged in over real HTTP, separately from the primary", () => {
    // Both real logins already happened once in beforeAll — see the
    // module-level comment for why this doesn't perform a second, fresh
    // login here (a real TOTP code can only be verified once per step).
    expect(typeof backupToken).toBe("string");
    expect(backupToken.length).toBeGreaterThan(0);
    expect(backupToken).not.toBe(primaryToken);
  });
});

describe("ADR-019: real escalation over real HTTP", () => {
  it("the primary can decide within the decision window", async () => {
    const requestId = await submitRequest(primaryToken, "accountability-agent-1");

    const res = await fetch(`${baseUrl}/requests/${requestId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${primaryToken}` },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(200);
  });

  it("once the window expires, the primary is rejected with a real 403, and the backup can decide instead", async () => {
    const requestId = await submitRequest(primaryToken, "accountability-agent-2");

    await new Promise((resolve) => setTimeout(resolve, 200)); // past the 150ms window

    const rejected = await fetch(`${baseUrl}/requests/${requestId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${primaryToken}` },
      body: JSON.stringify({}),
    });
    expect(rejected.status).toBe(403);

    const approved = await fetch(`${baseUrl}/requests/${requestId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${backupToken}` },
      body: JSON.stringify({}),
    });
    expect(approved.status).toBe(200);

    const entries: Array<Record<string, unknown>> = await fetch(`${baseUrl}/audit-log`).then((r) => r.json());
    expect(entries).toContainEqual(expect.objectContaining({ requestId, decision: "request_escalated" }));
    expect(entries).toContainEqual(
      expect.objectContaining({ requestId, decision: "request_decision_rejected", actor: PRIMARY_USERNAME }),
    );
    expect(entries).toContainEqual(expect.objectContaining({ requestId, decision: "request_approved", actor: BACKUP_USERNAME }));
  });
});
