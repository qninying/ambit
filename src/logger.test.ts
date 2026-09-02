import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logEvent } from "./logger.js";

describe("logEvent", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  function lastLoggedLine(): Record<string, unknown> {
    expect(logSpy).toHaveBeenCalledTimes(1);
    return JSON.parse(logSpy.mock.calls[0]![0] as string);
  }

  it("logs exactly one line, to console.log (not console.error) — no MCP stdout constraint here", () => {
    logEvent({ level: "info", event: "test_event" });
    expect(logSpy).toHaveBeenCalledTimes(1);
  });

  it("produces valid JSON with the required fields", () => {
    logEvent({ level: "warn", event: "test_event", context: { foo: "bar" } });
    const parsed = lastLoggedLine();
    expect(parsed).toMatchObject({ level: "warn", service: "ambit", event: "test_event", context: { foo: "bar" } });
    expect(typeof parsed.timestamp).toBe("string");
    expect(new Date(parsed.timestamp as string).toString()).not.toBe("Invalid Date");
  });

  it("defaults context to an empty object when none is given", () => {
    logEvent({ level: "error", event: "test_event" });
    expect(lastLoggedLine().context).toEqual({});
  });

  it("supports all three log levels", () => {
    for (const level of ["info", "warn", "error"] as const) {
      logEvent({ level, event: "test_event" });
      expect(lastLoggedLine().level).toBe(level);
      logSpy.mockClear();
    }
  });
});
