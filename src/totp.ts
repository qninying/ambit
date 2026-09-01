// ADR-017: real TOTP (RFC 6238, built on HOTP/RFC 4226), closing the
// INPACT Identity dimension's remaining named gap — no second factor on
// operator login. Hand-rolled with node:crypto's HMAC-SHA1, zero new
// dependencies, same "hand-roll small auth primitives" precedent already
// set by passwordHash.ts (scrypt) and sessionToken.ts (HMAC signing).
// Ported from CoreOps's own totp.ts — same problem, same right-sized
// answer, not reinvented.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// node:crypto has no base32 support (only hex/base64), and TOTP secrets/URIs
// are conventionally base32 for authenticator-app compatibility (RFC 4648).
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  while (output.length % 8 !== 0) {
    output += "=";
  }
  return output;
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid base32 character: "${char}"`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export interface TotpCodeOptions {
  stepSeconds?: number;
  digits?: number;
}

// RFC 4226 HOTP over an RFC 6238 time-derived counter. digits defaults to 6
// (the real login's setting); the RFC's own Appendix B test vectors use 8,
// so tests pass digits explicitly rather than relying on this default.
export function generateTotpCode(secretBase32: string, timeMs: number, options: TotpCodeOptions = {}): string {
  const stepSeconds = options.stepSeconds ?? 30;
  const digits = options.digits ?? 6;
  const counter = Math.floor(timeMs / 1000 / stepSeconds);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(0, 0);
  counterBuffer.writeUInt32BE(counter, 4);

  const key = base32Decode(secretBase32);
  const hmac = createHmac("sha1", key).update(counterBuffer).digest();

  const offset = hmac[hmac.length - 1]! & 0x0f;
  const truncated =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return (truncated % 10 ** digits).toString().padStart(digits, "0");
}

// Standard Key URI Format every mainstream authenticator app parses for
// manual entry — no QR image generation here (hand-rolling a correct QR
// encoder is genuinely complex and disproportionate for this system; every
// mainstream authenticator app also accepts a manual base32 secret).
export function buildOtpAuthUri(secretBase32: string, accountName: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf-8");
  const bBuf = Buffer.from(b, "utf-8");
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

export interface TotpVerifierOptions {
  stepSeconds?: number;
  digits?: number;
  driftSteps?: number;
  now?: () => number;
}

// Owns replay protection: a code can't be reused within its own drift
// window, but isn't permanently burned either — the next real code, once
// the clock has moved past lastAcceptedTimestep, verifies normally. Same
// injectable-clock shape as RateLimiter/CircuitBreaker for deterministic
// testing.
export class TotpVerifier {
  #secret: string;
  #stepSeconds: number;
  #digits: number;
  #driftSteps: number;
  #now: () => number;
  #lastAcceptedTimestep: number | null = null;

  constructor(secretBase32: string, options: TotpVerifierOptions = {}) {
    this.#secret = secretBase32;
    this.#stepSeconds = options.stepSeconds ?? 30;
    this.#digits = options.digits ?? 6;
    this.#driftSteps = options.driftSteps ?? 1;
    this.#now = options.now ?? (() => Date.now());
  }

  verify(code: string): boolean {
    const currentTimestep = Math.floor(this.#now() / 1000 / this.#stepSeconds);

    for (let delta = -this.#driftSteps; delta <= this.#driftSteps; delta++) {
      const timestep = currentTimestep + delta;
      if (this.#lastAcceptedTimestep !== null && timestep <= this.#lastAcceptedTimestep) {
        continue;
      }
      const candidate = generateTotpCode(this.#secret, timestep * this.#stepSeconds * 1000, {
        stepSeconds: this.#stepSeconds,
        digits: this.#digits,
      });
      if (constantTimeEqual(candidate, code)) {
        this.#lastAcceptedTimestep = timestep;
        return true;
      }
    }
    return false;
  }
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20)); // 160 bits, RFC 6238's recommended minimum
}
