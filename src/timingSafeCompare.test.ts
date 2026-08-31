import { describe, expect, it } from "vitest";
import { timingSafeStringEqual } from "./timingSafeCompare.js";

describe("timingSafeStringEqual", () => {
  it("returns true for identical strings", () => {
    expect(timingSafeStringEqual("correct-secret", "correct-secret")).toBe(true);
  });

  it("returns false for different strings of the same length", () => {
    expect(timingSafeStringEqual("correct-secret", "wrong--secret")).toBe(false);
  });

  it("returns false for strings of different lengths, without throwing", () => {
    expect(() => timingSafeStringEqual("short", "a-much-longer-value-entirely")).not.toThrow();
    expect(timingSafeStringEqual("short", "a-much-longer-value-entirely")).toBe(false);
  });

  it("returns true for two empty strings", () => {
    expect(timingSafeStringEqual("", "")).toBe(true);
  });

  it("returns false when only one side is empty", () => {
    expect(timingSafeStringEqual("", "not-empty")).toBe(false);
  });

  it("is case-sensitive", () => {
    expect(timingSafeStringEqual("Secret", "secret")).toBe(false);
  });
});
