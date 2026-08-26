import { describe, expect, it } from "vitest";
import { issueToken } from "./token.js";
import { TokenStore } from "./tokenStore.js";

describe("TokenStore.list", () => {
  it("returns an empty list when nothing has been issued", () => {
    const store = new TokenStore();
    expect(store.list()).toEqual([]);
  });

  it("returns every token issued, in this store", () => {
    const store = new TokenStore();
    const a = issueToken({ subject: "agent-1", scope: ["email:send"], ttlSeconds: 300 }, store);
    const b = issueToken({ subject: "agent-2", scope: ["crm:read"], ttlSeconds: 300 }, store);

    const list = store.list();
    expect(list).toHaveLength(2);
    expect(list.map((t) => t.id).sort()).toEqual([a.id, b.id].sort());
  });
});
