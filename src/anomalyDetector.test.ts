import { describe, expect, it } from "vitest";
import { AnomalyDetector } from "./anomalyDetector.js";

describe("AnomalyDetector", () => {
  it("does not flag a single, reasonably-scoped request", () => {
    const detector = new AnomalyDetector();
    const result = detector.check("agent-42", ["email:send"], new Date());
    expect(result).toEqual({ anomalous: false, signals: [] });
  });

  it("flags a request whose scope is unusually broad", () => {
    const detector = new AnomalyDetector();
    const result = detector.check("agent-42", ["email:send", "payment:charge", "sms:send", "crm:read"], new Date());
    expect(result.anomalous).toBe(true);
    expect(result.signals).toContain("scope_too_broad");
  });

  it("flags a burst of requests from the same subject within the window", () => {
    const detector = new AnomalyDetector();
    const t0 = new Date("2026-01-01T00:00:00Z");
    detector.check("agent-42", ["email:send"], new Date(t0.getTime() + 0));
    detector.check("agent-42", ["email:send"], new Date(t0.getTime() + 1_000));
    detector.check("agent-42", ["email:send"], new Date(t0.getTime() + 2_000));
    const fourth = detector.check("agent-42", ["email:send"], new Date(t0.getTime() + 3_000));

    expect(fourth.anomalous).toBe(true);
    expect(fourth.signals).toContain("high_velocity");
  });

  // Guards against the "false positive alert" failure path: one agent's
  // burst must not flag an unrelated agent that happens to request around
  // the same time.
  it("tracks velocity per subject, not globally", () => {
    const detector = new AnomalyDetector();
    const t0 = new Date("2026-01-01T00:00:00Z");
    detector.check("agent-42", ["email:send"], t0);
    detector.check("agent-42", ["email:send"], t0);
    detector.check("agent-42", ["email:send"], t0);
    detector.check("agent-42", ["email:send"], t0);

    const otherAgent = detector.check("agent-99", ["email:send"], t0);
    expect(otherAgent.anomalous).toBe(false);
  });

  it("does not count a request outside the velocity window", () => {
    const detector = new AnomalyDetector();
    const t0 = new Date("2026-01-01T00:00:00Z");
    detector.check("agent-42", ["email:send"], t0);
    detector.check("agent-42", ["email:send"], t0);
    detector.check("agent-42", ["email:send"], t0);

    const wellAfterWindow = new Date(t0.getTime() + 5 * 60_000);
    const result = detector.check("agent-42", ["email:send"], wellAfterWindow);
    expect(result.anomalous).toBe(false);
  });

  // Thresholds are configurable, not hardcoded magic — this proves the
  // config actually changes behavior, not just that the constructor accepts it.
  it("honors a custom maxScopeBreadth instead of the default", () => {
    const strict = new AnomalyDetector({ maxScopeBreadth: 1 });
    const result = strict.check("agent-42", ["email:send", "payment:charge"], new Date());
    expect(result.signals).toContain("scope_too_broad");

    // The same request would NOT be flagged under the default config.
    const lenient = new AnomalyDetector();
    expect(lenient.check("agent-99", ["email:send", "payment:charge"], new Date()).anomalous).toBe(false);
  });

  it("honors a custom maxRequestsPerWindow instead of the default", () => {
    const detector = new AnomalyDetector({ maxRequestsPerWindow: 1 });
    const t0 = new Date("2026-01-01T00:00:00Z");
    detector.check("agent-42", ["email:send"], t0);
    const second = detector.check("agent-42", ["email:send"], t0);
    expect(second.signals).toContain("high_velocity");
  });

  it("falls back to the default for any config field left unset", () => {
    const detector = new AnomalyDetector({ maxScopeBreadth: 1 });
    // velocityWindowMs/maxRequestsPerWindow weren't overridden — default
    // velocity behavior (3 requests before a 4th trips it) should still hold.
    const t0 = new Date("2026-01-01T00:00:00Z");
    detector.check("agent-42", ["x"], t0);
    detector.check("agent-42", ["x"], t0);
    const third = detector.check("agent-42", ["x"], t0);
    expect(third.signals).not.toContain("high_velocity");
  });
});
