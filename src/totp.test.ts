import { describe, it, expect } from "vitest";
import { base32Encode, base32Decode, generateTotpCode, buildOtpAuthUri, TotpVerifier } from "./totp.js";

// RFC 6238 Appendix B's own SHA1 test vectors, ASCII secret "12345678901234567890",
// 8 digits, 30s step. Verified against the published values, not just internal
// generate-then-verify self-consistency — this is the load-bearing correctness
// check for the whole module.
const RFC_SECRET_BASE32 = base32Encode(Buffer.from("12345678901234567890", "ascii"));

describe("base32Encode / base32Decode", () => {
  it("round-trips arbitrary bytes", () => {
    const original = Buffer.from([0, 1, 2, 254, 255, 128, 42, 17]);
    expect(base32Decode(base32Encode(original))).toEqual(original);
  });

  it("matches a known fixed vector", () => {
    // RFC 4648 Sec 10's own test vector: "foobar" -> "MZXW6YTBOI======"
    expect(base32Encode(Buffer.from("foobar", "ascii"))).toBe("MZXW6YTBOI======");
    expect(base32Decode("MZXW6YTBOI======").toString("ascii")).toBe("foobar");
  });

  it("rejects an invalid character", () => {
    expect(() => base32Decode("!!!!!!!!")).toThrow();
  });
});

describe("generateTotpCode — RFC 6238 Appendix B vectors", () => {
  it.each([
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ])("T=%i -> %s", (unixSeconds, expectedCode) => {
    const code = generateTotpCode(RFC_SECRET_BASE32, unixSeconds * 1000, { digits: 8 });
    expect(code).toBe(expectedCode);
  });

  it("a 6-digit code is the last 6 digits of the 8-digit RFC vector", () => {
    const code8 = generateTotpCode(RFC_SECRET_BASE32, 59_000, { digits: 8 });
    const code6 = generateTotpCode(RFC_SECRET_BASE32, 59_000, { digits: 6 });
    expect(code6).toBe(code8.slice(-6));
  });
});

describe("buildOtpAuthUri", () => {
  it("includes the required Key URI Format fields", () => {
    const uri = buildOtpAuthUri("JBSWY3DPEHPK3PXP", "operator", "Ambit");
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(uri).toContain("Ambit:operator");
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP");
    expect(uri).toContain("issuer=Ambit");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("URL-encodes an issuer/account containing special characters", () => {
    const uri = buildOtpAuthUri("JBSWY3DPEHPK3PXP", "a b", "Amb it");
    expect(uri).toContain("Amb%20it:a%20b");
  });
});

describe("TotpVerifier", () => {
  const secret = base32Encode(Buffer.from("test-secret-1234567", "ascii"));
  const stepSeconds = 30;

  function codeAt(unixSeconds: number): string {
    return generateTotpCode(secret, unixSeconds * 1000, { stepSeconds });
  }

  it("accepts a code generated for the current time", () => {
    const nowMs = 1_700_000_000_000;
    const verifier = new TotpVerifier(secret, { now: () => nowMs });
    const code = codeAt(Math.floor(nowMs / 1000));
    expect(verifier.verify(code)).toBe(true);
  });

  it("rejects a wrong code", () => {
    const verifier = new TotpVerifier(secret, { now: () => 1_700_000_000_000 });
    expect(verifier.verify("000000")).toBe(false);
  });

  it("accepts a code from one step in the past or future (drift tolerance)", () => {
    const baseSeconds = 1_700_000_000;
    const nowMs = baseSeconds * 1000;

    const verifierPast = new TotpVerifier(secret, { now: () => nowMs });
    expect(verifierPast.verify(codeAt(baseSeconds - stepSeconds))).toBe(true);

    const verifierFuture = new TotpVerifier(secret, { now: () => nowMs });
    expect(verifierFuture.verify(codeAt(baseSeconds + stepSeconds))).toBe(true);
  });

  it("rejects a code two steps outside the current window", () => {
    const baseSeconds = 1_700_000_000;
    const verifier = new TotpVerifier(secret, { now: () => baseSeconds * 1000 });
    expect(verifier.verify(codeAt(baseSeconds - 2 * stepSeconds))).toBe(false);
    expect(verifier.verify(codeAt(baseSeconds + 2 * stepSeconds))).toBe(false);
  });

  it("rejects a replay of the exact same code, even though it was just valid", () => {
    const baseSeconds = 1_700_000_000;
    const verifier = new TotpVerifier(secret, { now: () => baseSeconds * 1000 });
    const code = codeAt(baseSeconds);
    expect(verifier.verify(code)).toBe(true);
    expect(verifier.verify(code)).toBe(false);
  });

  it("is not a permanent lockout — a fresh code verifies once time has moved on", () => {
    let nowSeconds = 1_700_000_000;
    const verifier = new TotpVerifier(secret, { now: () => nowSeconds * 1000 });

    expect(verifier.verify(codeAt(nowSeconds))).toBe(true);

    // Advance well past the accepted timestep's drift window.
    nowSeconds += stepSeconds * 3;
    expect(verifier.verify(codeAt(nowSeconds))).toBe(true);
  });
});
