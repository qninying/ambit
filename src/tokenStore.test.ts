import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueToken, revokeToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";
import { AuditLog } from "./auditLog.js";

describe("TokenStore.list", () => {
  it("returns an empty list when nothing has been issued", () => {
    const store = new TokenStore();
    expect(store.list()).toEqual([]);
  });

  it("returns every token issued, in this store", async () => {
    const store = new TokenStore();
    const { token: a } = await issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, store);
    const { token: b } = await issueToken({ subject: "agent-2", scope: ["crm:read"], ttlSeconds: 300 }, store);

    const list = store.list();
    expect(list).toHaveLength(2);
    expect(list.map((t) => t.id).sort()).toEqual([a.id, b.id].sort());
  });
});

// ADR-014: proves the actual point — a token genuinely survives a restart,
// not just that save()/rehydrate() were called somewhere.
describe("TokenStore persistence (ADR-014)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ambit-tokenstore-test-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("a token issued before a restart is still there — same data — after one", async () => {
    const file = join(dir, "tokens.jsonl");
    const before = new TokenStore(undefined, file);
    const { token } = await issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, before);

    // A genuinely new store instance — the real proof, not the same object.
    const after = new TokenStore(undefined, file);
    expect(after.get(token.id)).toEqual(token);
    expect(after.get(token.id)?.issuedAt).toBeInstanceOf(Date);
    expect(after.get(token.id)?.expiresAt).toBeInstanceOf(Date);
  });

  it("a later update (revocation) correctly supersedes the earlier issuance after a restart", async () => {
    const file = join(dir, "tokens.jsonl");
    const auditLog = new AuditLog();
    const before = new TokenStore(undefined, file);
    const { token } = await issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, before);
    revokeToken(token.id, before, auditLog, "compromised");

    const after = new TokenStore(undefined, file);
    expect(after.get(token.id)?.status).toBe("revoked");
    expect(after.get(token.id)?.revokedAt).toBeInstanceOf(Date);
  });

  it("a store with no persistTo behaves exactly as before this ADR — nothing written, nothing rehydrated", async () => {
    const store = new TokenStore();
    await issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, store);
    // No file path was ever given — there's nothing to assert against on
    // disk; the real assertion is simply that this never throws.
    expect(store.list()).toHaveLength(1);
  });
});
