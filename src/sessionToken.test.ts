import { describe, expect, it } from "vitest";
import { createSessionToken, verifySessionToken } from "./sessionToken.js";

const config = { signingSecret: "test-signing-secret-do-not-use-in-prod" };

describe("createSessionToken / verifySessionToken", () => {
  it("round-trips: a freshly created token verifies with the right username", () => {
    const token = createSessionToken("alice", config);
    const result = verifySessionToken(token, config);

    expect(result).toEqual({ valid: true, username: "alice" });
  });

  it("rejects a token once it has expired", () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const token = createSessionToken("alice", { ...config, ttlMs: 1000 }, now);

    const stillValid = verifySessionToken(token, config, new Date(now.getTime() + 999));
    expect(stillValid.valid).toBe(true);

    const expired = verifySessionToken(token, config, new Date(now.getTime() + 1000));
    expect(expired).toEqual({ valid: false, reason: "expired" });
  });

  it("rejects a token signed with a different secret", () => {
    const token = createSessionToken("alice", config);
    const result = verifySessionToken(token, { signingSecret: "a-completely-different-secret" });

    expect(result).toEqual({ valid: false, reason: "invalid_signature" });
  });

  // The security-critical case: tampering with the payload (e.g. trying to
  // change the username) must invalidate the signature, not silently parse
  // into a different valid session.
  it("rejects a token whose payload was tampered with after signing", () => {
    const token = createSessionToken("alice", config);
    const [payloadB64, signature] = token.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ username: "admin", issuedAt: 0, expiresAt: Date.now() + 999999 }), "utf8").toString(
      "base64url",
    );
    const tamperedToken = `${tamperedPayload}.${signature}`;

    expect(verifySessionToken(tamperedToken, config)).toEqual({ valid: false, reason: "invalid_signature" });
  });

  it("rejects a malformed token (no signature part) without throwing", () => {
    expect(() => verifySessionToken("not-a-real-token", config)).not.toThrow();
    expect(verifySessionToken("not-a-real-token", config).valid).toBe(false);
  });

  it("rejects a token with a valid-looking signature but garbage payload", () => {
    expect(verifySessionToken("Z2FyYmFnZQ.somesignature", config).valid).toBe(false);
  });

  it("respects a configurable TTL rather than a hardcoded one", () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const shortLived = createSessionToken("alice", { ...config, ttlMs: 50 }, now);
    const longLived = createSessionToken("alice", { ...config, ttlMs: 50_000 }, now);
    const later = new Date(now.getTime() + 100);

    expect(verifySessionToken(shortLived, config, later).valid).toBe(false);
    expect(verifySessionToken(longLived, config, later).valid).toBe(true);
  });
});
