// ADR-009 hardening: a real, verifiable operator session — not a hardcoded
// "demo-approver" string the client could set to anything. A minimal
// hand-rolled signed token (HMAC-SHA256 over a JSON payload) rather than
// pulling in a JWT library as a new dependency: the actual cryptographic
// need here — sign a small payload, verify it wasn't tampered with, check
// an expiry — is small enough that node:crypto covers it completely, same
// "no new dependency without a deliberate reason" standard as everywhere
// else in this build.

import { createHmac } from "node:crypto";
import { timingSafeStringEqual } from "./timingSafeCompare.js";

export interface SessionTokenConfig {
  signingSecret: string;
  ttlMs?: number;
}

// A judgment call, not hardcoded — overridable via config, and via
// SESSION_TTL_MS in server.ts, same treatment as every other threshold here.
export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

interface SessionPayload {
  username: string;
  issuedAt: number;
  expiresAt: number;
}

function sign(payloadB64: string, secret: string): string {
  return createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

export function createSessionToken(username: string, config: SessionTokenConfig, now: Date = new Date()): string {
  const ttlMs = config.ttlMs ?? DEFAULT_SESSION_TTL_MS;
  const payload: SessionPayload = { username, issuedAt: now.getTime(), expiresAt: now.getTime() + ttlMs };
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${payloadB64}.${sign(payloadB64, config.signingSecret)}`;
}

export type SessionVerifyResult =
  | { valid: true; username: string }
  | { valid: false; reason: "malformed" | "invalid_signature" | "expired" };

// Never throws — same "always a decision, not an exception" contract as
// enforceToken/delegateToken elsewhere in this codebase. A malformed or
// tampered token is just another kind of "not valid," not a crash.
export function verifySessionToken(token: string, config: SessionTokenConfig, now: Date = new Date()): SessionVerifyResult {
  const parts = token.split(".");
  if (parts.length !== 2) return { valid: false, reason: "malformed" };
  const [payloadB64, signature] = parts as [string, string];

  // Signature checked BEFORE the payload is parsed or trusted at all — an
  // attacker-controlled payload never gets read until it's proven to have
  // come from this server's own signing secret.
  if (!timingSafeStringEqual(signature, sign(payloadB64, config.signingSecret))) {
    return { valid: false, reason: "invalid_signature" };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    typeof (payload as SessionPayload).username !== "string" ||
    typeof (payload as SessionPayload).expiresAt !== "number"
  ) {
    return { valid: false, reason: "malformed" };
  }

  const { username, expiresAt } = payload as SessionPayload;
  if (now.getTime() >= expiresAt) return { valid: false, reason: "expired" };
  return { valid: true, username };
}
