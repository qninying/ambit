// ADR-009 hardening: real operator authentication needs a real password
// check, not a plaintext comparison against an env var. scrypt (built into
// node:crypto, no new dependency) is deliberately slow and memory-hard,
// which is the point — it makes brute-forcing a stolen hash expensive even
// though there's only one admin account here, not a database of many.

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

const SALT_BYTES = 16;
const KEY_LENGTH = 64;

// Format: "<saltHex>:<hashHex>" — self-describing, no separate config
// needed to verify later, same reasoning most real password-hash libraries
// use for their own encoded output.
export async function hashPassword(plaintext: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const derived = (await scrypt(plaintext, salt, KEY_LENGTH)) as Buffer;
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

export async function verifyPassword(plaintext: string, storedHash: string): Promise<boolean> {
  const [saltHex, hashHex] = storedHash.split(":");
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = (await scrypt(plaintext, salt, expected.length)) as Buffer;
  // Constant-time — same reasoning as timingSafeCompare.ts, and the two
  // buffers are always the same length here (both derived with the same
  // KEY_LENGTH), so there's no length-based early exit to worry about.
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
