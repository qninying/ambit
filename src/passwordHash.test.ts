import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./passwordHash.js";

describe("hashPassword / verifyPassword", () => {
  it("verifies the correct password against its own hash", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("wrong password", hash)).toBe(false);
  });

  it("never stores the plaintext password in the hash output", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).not.toContain("correct horse battery staple");
  });

  it("produces a different hash each time for the same password (real salting)", async () => {
    const hashA = await hashPassword("same-password");
    const hashB = await hashPassword("same-password");
    expect(hashA).not.toBe(hashB);
    // Both still verify correctly — the salt differs, not the correctness.
    expect(await verifyPassword("same-password", hashA)).toBe(true);
    expect(await verifyPassword("same-password", hashB)).toBe(true);
  });

  it("rejects a malformed stored hash instead of throwing", async () => {
    expect(await verifyPassword("anything", "not-a-real-hash-format")).toBe(false);
  });

  it("is case-sensitive", async () => {
    const hash = await hashPassword("Password123");
    expect(await verifyPassword("password123", hash)).toBe(false);
  });
});
