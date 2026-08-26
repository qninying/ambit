import { describe, expect, it, vi } from "vitest";
import { CircuitBreaker, CircuitOpenError } from "./circuitBreaker.js";

describe("CircuitBreaker", () => {
  it("starts closed and lets calls through, returning the function's result", () => {
    const breaker = new CircuitBreaker();
    expect(breaker.state()).toBe("closed");
    expect(breaker.execute(() => 42)).toBe(42);
  });

  it("opens after the configured number of consecutive failures, not before", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    const failing = () => { throw new Error("boom"); };

    expect(() => breaker.execute(failing)).toThrow("boom");
    expect(breaker.state()).toBe("closed");
    expect(() => breaker.execute(failing)).toThrow("boom");
    expect(breaker.state()).toBe("closed");
    expect(() => breaker.execute(failing)).toThrow("boom");
    expect(breaker.state()).toBe("open");
  });

  // Acceptance: "Given the Store is reachable, when a request is made, then
  // it is processed." — an intermittent failure that never reaches the
  // threshold must not trip the breaker.
  it("resets the failure count on a success, so intermittent failures don't accumulate toward the threshold", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    const failing = () => { throw new Error("boom"); };

    expect(() => breaker.execute(failing)).toThrow();
    expect(() => breaker.execute(failing)).toThrow();
    breaker.execute(() => "ok"); // resets the streak
    expect(() => breaker.execute(failing)).toThrow();
    expect(() => breaker.execute(failing)).toThrow();
    expect(breaker.state()).toBe("closed"); // only 2 consecutive again, not 4 total
  });

  // Acceptance: "Given the Policy & Token Store is unreachable, when a
  // request is made, then it is denied." — proven here as "the wrapped
  // function is never even called while open," the same standard STORY-005
  // set for a denied token never reaching the mock endpoint.
  it("throws CircuitOpenError without calling the wrapped function while open", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 10_000 });
    expect(() => breaker.execute(() => { throw new Error("boom"); }, new Date(0))).toThrow();
    expect(breaker.state()).toBe("open");

    const fn = vi.fn(() => "should not run");
    expect(() => breaker.execute(fn, new Date(1_000))).toThrow(CircuitOpenError);
    expect(fn).not.toHaveBeenCalled();
  });

  it("moves to half-open and allows exactly one trial call once the cooldown has elapsed", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 5_000 });
    expect(() => breaker.execute(() => { throw new Error("boom"); }, new Date(0))).toThrow();
    expect(breaker.state()).toBe("open");

    // Before cooldown: still denied, still not called.
    const tooEarly = vi.fn(() => "ok");
    expect(() => breaker.execute(tooEarly, new Date(4_999))).toThrow(CircuitOpenError);
    expect(tooEarly).not.toHaveBeenCalled();

    // After cooldown: the trial probe actually runs.
    const probe = vi.fn(() => "ok");
    const result = breaker.execute(probe, new Date(5_001));
    expect(probe).toHaveBeenCalledTimes(1);
    expect(result).toBe("ok");
    expect(breaker.state()).toBe("closed");
  });

  it("reopens (and restarts the cooldown) when the trial probe itself fails", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 5_000 });
    expect(() => breaker.execute(() => { throw new Error("boom"); }, new Date(0))).toThrow();

    expect(() => breaker.execute(() => { throw new Error("still down"); }, new Date(5_001))).toThrow();
    expect(breaker.state()).toBe("open");

    // Cooldown restarted from the failed probe's time (5001), not the
    // original trip (0) — a call at 9000 (< 5001+5000) is still denied.
    const tooEarly = vi.fn();
    expect(() => breaker.execute(tooEarly, new Date(9_000))).toThrow(CircuitOpenError);
    expect(tooEarly).not.toHaveBeenCalled();
  });

  // The deterministic fault-injection hook this story's acceptance actually
  // depends on — proves it drives the *real* threshold/state logic, not a
  // separate fake path.
  it("simulateOutage(true) genuinely feeds the failure-counting logic, not just a manual override", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 2 });
    breaker.simulateOutage(true);

    expect(() => breaker.execute(() => "would have worked")).toThrow(CircuitOpenError);
    expect(breaker.state()).toBe("closed"); // 1 of 2 — not yet tripped
    expect(() => breaker.execute(() => "would have worked")).toThrow(CircuitOpenError);
    expect(breaker.state()).toBe("open"); // threshold reached
  });

  it("simulateOutage(false) lets a subsequent half-open probe succeed for real", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1_000 });
    breaker.simulateOutage(true);
    expect(() => breaker.execute(() => "unreachable", new Date(0))).toThrow();
    expect(breaker.state()).toBe("open");

    breaker.simulateOutage(false);
    const result = breaker.execute(() => "real result", new Date(2_000));
    expect(result).toBe("real result");
    expect(breaker.state()).toBe("closed");
  });

  // Trust: circuit-breaker actions are logged — this is the hook server.ts
  // wires to the audit log. Only the two trust-relevant transitions notify;
  // the internal open->half_open waypoint (a probe attempt, not a
  // resolution) deliberately does not.
  it("calls onStateChange for the open and close transitions, but not for the internal half-open probe waypoint", () => {
    const changes: Array<{ from: string; to: string; reason: string }> = [];
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1_000 }, (c) => changes.push(c));

    expect(() => breaker.execute(() => { throw new Error("boom"); }, new Date(0))).toThrow();
    expect(changes).toEqual([{ from: "closed", to: "open", reason: "failure_threshold_reached" }]);

    breaker.execute(() => "recovered", new Date(2_000));
    expect(changes).toEqual([
      { from: "closed", to: "open", reason: "failure_threshold_reached" },
      { from: "half_open", to: "closed", reason: "probe_succeeded" },
    ]);
  });

  it("is configurable — a lower threshold and shorter cooldown are not hardcoded", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 100 });
    expect(() => breaker.execute(() => { throw new Error("boom"); }, new Date(0))).toThrow();
    expect(breaker.state()).toBe("open");
    // Would still be open at 5000ms under the default 5s cooldown; this
    // config recovers by 101ms because the constructor value actually took.
    const result = breaker.execute(() => "recovered", new Date(101));
    expect(result).toBe("recovered");
  });
});
