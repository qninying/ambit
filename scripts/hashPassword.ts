// One-off operational script: generate an ADMIN_PASSWORD_HASH value for
// server.ts's real operator login (ADR-009 hardening) — the operator never
// has to put a raw password into an env var, only this hash.
//
// Usage: npm run hash-password -- 'your real password'
//
// The password is a CLI argument, which does land in shell history — an
// accepted tradeoff for a one-time local setup tool, not a production
// secrets pipeline. Clear it from your shell history afterward if that
// matters in your environment.

import { hashPassword } from "../src/passwordHash.js";

const password = process.argv[2];
if (!password) {
  console.error("Usage: npm run hash-password -- 'your real password'");
  process.exit(1);
}

const hash = await hashPassword(password);
console.log("");
console.log("ADMIN_PASSWORD_HASH=" + hash);
console.log("");
console.log("Set this (and ADMIN_USERNAME, SESSION_SIGNING_SECRET) as real env vars —");
console.log("never commit them, and never put the raw password anywhere else.");
