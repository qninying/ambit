// Constant-time comparison for secret values (e.g. the admin toggle key).
// A plain === or !== on strings short-circuits at the first differing
// character — an attacker measuring response timing over enough requests
// could use that to recover a secret one character at a time. Node's
// crypto.timingSafeEqual is constant-time but requires equal-length
// buffers (it throws otherwise); hashing both values to a fixed length
// first avoids that entirely, rather than adding an early-exit length
// check that would itself leak the secret's length.

import { createHash, timingSafeEqual } from "node:crypto";

export function timingSafeStringEqual(a: string, b: string): boolean {
  const hashA = createHash("sha256").update(a, "utf8").digest();
  const hashB = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(hashA, hashB);
}
