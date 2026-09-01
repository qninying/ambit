// One-off operational script: generate an ADMIN_TOTP_SECRET value for
// server.ts's real operator login (ADR-017, closing the INPACT Identity
// dimension's MFA gap). Not part of the running app — run by hand, once,
// as enrollment: paste the printed secret into your env, then enter it
// (manually, or via the printed otpauth:// URI) into an authenticator app.
// Mirrors hashPassword.ts's own "generate -> paste into env -> never commit
// the raw value" setup pattern exactly.
//
// Usage: npm run generate-totp-secret -- [account-name]
// account-name defaults to ADMIN_USERNAME, then "operator", if neither is set.

import { buildOtpAuthUri, generateTotpSecret } from "../src/totp.js";

const accountName = process.argv[2] ?? process.env.ADMIN_USERNAME ?? "operator";
const secret = generateTotpSecret();
const uri = buildOtpAuthUri(secret, accountName, "Ambit");

console.log("");
console.log("ADMIN_TOTP_SECRET=" + secret);
console.log("");
console.log("Enter this into your authenticator app — manual entry, or paste this URI:");
console.log(uri);
console.log("");
console.log("Set ADMIN_TOTP_SECRET as a real env var — never commit it. Once set, every");
console.log("login requires the current 6-digit code from your authenticator app too.");
