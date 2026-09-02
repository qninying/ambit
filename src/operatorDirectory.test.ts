import { describe, it, expect, beforeAll } from "vitest";
import { hashPassword } from "./passwordHash.js";
import { findAuthenticatedOperator, type OperatorIdentity } from "./operatorDirectory.js";

let primaryHash: string;
let backupHash: string;

beforeAll(async () => {
  primaryHash = await hashPassword("primary-password");
  backupHash = await hashPassword("backup-password");
});

// Fake verifiers, not real TotpVerifier instances — real TOTP correctness is
// totp.test.ts's job. Each identity's fake only accepts its own designated
// code, so a mismatch across identities is structurally impossible to
// fake-pass.
function fakeVerifier(acceptedCode: string): { verify(code: string): boolean } {
  return { verify: (code) => code === acceptedCode };
}

function directory(includeBackup: boolean): OperatorIdentity[] {
  const identities: OperatorIdentity[] = [{ username: "primary-user", passwordHash: primaryHash, totpVerifier: fakeVerifier("111111") }];
  if (includeBackup) {
    identities.push({ username: "backup-user", passwordHash: backupHash, totpVerifier: fakeVerifier("222222") });
  }
  return identities;
}

describe("findAuthenticatedOperator", () => {
  it("happy path: the correct primary identity matches", async () => {
    const match = await findAuthenticatedOperator(directory(true), "primary-user", "primary-password", "111111");
    expect(match?.username).toBe("primary-user");
  });

  it("happy path: the correct backup identity matches when configured", async () => {
    const match = await findAuthenticatedOperator(directory(true), "backup-user", "backup-password", "222222");
    expect(match?.username).toBe("backup-user");
  });

  it("failure path: wrong password for the primary identity is rejected", async () => {
    expect(await findAuthenticatedOperator(directory(true), "primary-user", "wrong-password", "111111")).toBeNull();
  });

  it("failure path: wrong password for the backup identity is rejected", async () => {
    expect(await findAuthenticatedOperator(directory(true), "backup-user", "wrong-password", "222222")).toBeNull();
  });

  it("failure path: wrong TOTP code for the primary identity is rejected", async () => {
    expect(await findAuthenticatedOperator(directory(true), "primary-user", "primary-password", "000000")).toBeNull();
  });

  it("failure path: wrong TOTP code for the backup identity is rejected", async () => {
    expect(await findAuthenticatedOperator(directory(true), "backup-user", "backup-password", "000000")).toBeNull();
  });

  it("boundary: an unconfigured backup identity (absent from the directory) never matches", async () => {
    expect(await findAuthenticatedOperator(directory(false), "backup-user", "backup-password", "222222")).toBeNull();
  });

  it("boundary: an unknown username matches no identity", async () => {
    expect(await findAuthenticatedOperator(directory(true), "nobody", "primary-password", "111111")).toBeNull();
  });

  it("boundary: cross-contamination — a code valid for one identity's verifier does not authenticate the other", async () => {
    // backup-user's real credentials, but the primary identity's TOTP code — must not match.
    expect(await findAuthenticatedOperator(directory(true), "backup-user", "backup-password", "111111")).toBeNull();
    // primary-user's real credentials, but the backup identity's TOTP code — must not match.
    expect(await findAuthenticatedOperator(directory(true), "primary-user", "primary-password", "222222")).toBeNull();
  });
});
