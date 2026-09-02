// ADR-019: Accountability hardening — a second real operator identity, so
// tokenRequest.ts's escalation (an unresolved request switching from the
// primary to a real backup approver) has an actual human behind it, not a
// hardcoded placeholder name. Extracted out of server.ts's POST /auth/login
// route specifically so the matching logic gets real unit tests, matching
// CoreOps's own userDirectory.ts precedent for the identical problem.

import { verifyPassword } from "./passwordHash.js";
import { timingSafeStringEqual } from "./timingSafeCompare.js";

// Structurally typed (not TotpVerifier directly) so tests can stub it
// without needing a real secret — real TOTP correctness is totp.test.ts's
// job.
export interface OperatorIdentity {
  username: string;
  passwordHash: string;
  totpVerifier: { verify(code: string): boolean };
}

// Loop order preserves the exact short-circuit property the single-
// operator login already had (ADR-017): a wrong password for a given
// identity never calls that identity's totpVerifier.verify(), so a
// mistyped password can't burn or replay-block that identity's currently-
// valid code. One generic null on no match, regardless of how many
// identities are configured or which one(s) partially matched — the caller
// (the login route) turns this into the same one generic 401 either way,
// preserving the anti-enumeration property across 1 or 2 possible
// identities.
export async function findAuthenticatedOperator(
  identities: readonly OperatorIdentity[],
  username: string,
  password: string,
  totpCode: string,
): Promise<OperatorIdentity | null> {
  for (const identity of identities) {
    // Username compared timing-safe too, same treatment the single-
    // operator login already gave it (ADR-011) — no reason to drop that
    // once there can be more than one identity to check against.
    if (
      timingSafeStringEqual(identity.username, username) &&
      (await verifyPassword(password, identity.passwordHash)) &&
      identity.totpVerifier.verify(totpCode)
    ) {
      return identity;
    }
  }
  return null;
}
