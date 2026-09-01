import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RequestStore } from "./requestStore.js";
import type { PendingRequest } from "./tokenRequest.js";

function pendingRequest(overrides: Partial<PendingRequest> = {}): PendingRequest {
  return {
    id: "req-1",
    subject: "agent-1",
    scope: ["email:send"],
    ttlSeconds: 300,
    status: "pending",
    requestedAt: new Date(),
    ...overrides,
  };
}

describe("RequestStore persistence (ADR-014)", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ambit-requeststore-test-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("a request submitted before a restart is still there, unchanged, after one", () => {
    const file = join(dir, "requests.jsonl");
    const before = new RequestStore(file);
    before.save(pendingRequest());

    const after = new RequestStore(file);
    const revived = after.get("req-1");
    expect(revived?.subject).toBe("agent-1");
    expect(revived?.requestedAt).toBeInstanceOf(Date);
  });

  // The core security property: ADR-013's transient, one-time-claimable
  // token secret must never touch disk — even correctly, even briefly. A
  // rehydrated request that still has status "approved" with an unclaimed
  // secret in memory would, if the plaintext leaked onto disk once, defeat
  // the entire point of making it claimable exactly once.
  it("NEVER writes tokenSecret to disk, even while it's legitimately present in memory", () => {
    const file = join(dir, "requests.jsonl");
    const store = new RequestStore(file);
    const secret = "super-secret-plaintext-that-must-never-hit-disk";
    store.save(pendingRequest({ status: "approved", tokenId: "tok-1", tokenSecret: secret }));

    const onDisk = readFileSync(file, "utf-8");
    expect(onDisk).not.toContain(secret);
    expect(onDisk).not.toContain("tokenSecret");

    // The in-memory copy still legitimately carries it — persistence
    // stripping it for the durable copy must not also break the real,
    // one-time claim flow that needs it in memory.
    expect(store.get("req-1")?.tokenSecret).toBe(secret);
  });

  // A direct consequence, named explicitly rather than left implicit: since
  // the secret never touched disk, a request that hadn't been claimed
  // before a restart can never be claimed after one — the rehydrated copy
  // has no tokenSecret to claim, by design, not by accident.
  it("a request's secret is unclaimable after a restart if it wasn't claimed before one", () => {
    const file = join(dir, "requests.jsonl");
    const before = new RequestStore(file);
    before.save(pendingRequest({ status: "approved", tokenId: "tok-1", tokenSecret: "never-claimed" }));

    const after = new RequestStore(file);
    expect(after.get("req-1")?.tokenSecret).toBeUndefined();
    expect(after.get("req-1")?.status).toBe("approved");
    expect(after.get("req-1")?.tokenId).toBe("tok-1");
  });

  it("a later update (approval) correctly supersedes the earlier pending state after a restart", () => {
    const file = join(dir, "requests.jsonl");
    const before = new RequestStore(file);
    before.save(pendingRequest({ status: "pending" }));
    before.save(pendingRequest({ status: "approved", tokenId: "tok-1", tokenSecret: "x" }));

    const after = new RequestStore(file);
    expect(after.get("req-1")?.status).toBe("approved");
    expect(after.pending()).toHaveLength(0);
  });
});
