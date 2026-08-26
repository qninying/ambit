// REQ-008: fail-closed circuit breaker for the Policy & Token Store. A
// generic, domain-agnostic state machine — closed (normal) -> open (failing
// fast, denying everything) -> half-open (cooldown elapsed, one trial call
// let through) -> closed on success or back to open on failure.
//
// TokenStore/PolicyStore are in-memory Maps (ADR-006) and can't fail on
// their own today, so this alone would have nothing real to react to.
// simulateOutage() is the deterministic fault-injection hook that gives it
// one — same pattern MockEndpointRegistry.setDown() already established for
// STORY-005 — and the failure-counting/threshold/cooldown/half-open logic
// below genuinely runs against that injected failure, not a manual override.

export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerConfig {
  failureThreshold: number;
  cooldownMs: number;
}

// Judgment calls, not universal truths — overridable via constructor and,
// in server.ts, via CIRCUIT_BREAKER_FAILURE_THRESHOLD/CIRCUIT_BREAKER_COOLDOWN_MS,
// same "no hardcoded magic" treatment as the anomaly detector's thresholds.
export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  cooldownMs: 5_000,
};

export class CircuitOpenError extends Error {
  constructor(message = "circuit breaker is open — the store is currently unreachable") {
    super(message);
    this.name = "CircuitOpenError";
  }
}

export type CircuitTransitionReason = "failure_threshold_reached" | "probe_succeeded" | "probe_failed";

export interface CircuitStateChange {
  from: CircuitState;
  to: CircuitState;
  reason: CircuitTransitionReason;
}

export class CircuitBreaker {
  #state: CircuitState = "closed";
  #consecutiveFailures = 0;
  #openedAt = 0;
  #simulatingOutage = false;
  #config: CircuitBreakerConfig;
  #onStateChange?: (change: CircuitStateChange) => void;

  constructor(config: Partial<CircuitBreakerConfig> = {}, onStateChange?: (change: CircuitStateChange) => void) {
    this.#config = {
      failureThreshold: config.failureThreshold ?? DEFAULT_CIRCUIT_BREAKER_CONFIG.failureThreshold,
      cooldownMs: config.cooldownMs ?? DEFAULT_CIRCUIT_BREAKER_CONFIG.cooldownMs,
    };
    this.#onStateChange = onStateChange;
  }

  state(): CircuitState {
    return this.#state;
  }

  // Test/demo-only fault injection — see the module comment above for why
  // this exists. Not gated behind an env flag: the same honesty-over-hiding
  // call this repo already made for MockEndpointRegistry.setDown().
  simulateOutage(down: boolean): void {
    this.#simulatingOutage = down;
  }

  // Runs fn() through the breaker. Throws CircuitOpenError (without ever
  // calling fn()) while fully open; lets exactly one trial call through as a
  // probe once the cooldown has elapsed. Callers decide what "denied" looks
  // like for their own contract — this only decides whether the underlying
  // operation runs at all.
  execute<T>(fn: () => T, now: Date = new Date()): T {
    if (this.#state === "open") {
      if (now.getTime() - this.#openedAt < this.#config.cooldownMs) {
        throw new CircuitOpenError();
      }
      // Cooldown elapsed — move to half-open and let this call be the
      // trial probe. Not itself a reason to notify: it's not yet a
      // resolution, just an attempt, so it's not written to the audit log.
      this.#state = "half_open";
    }

    try {
      if (this.#simulatingOutage) {
        throw new CircuitOpenError("simulated outage");
      }
      const result = fn();
      this.#onSuccess();
      return result;
    } catch (err) {
      this.#onFailure(now);
      throw err;
    }
  }

  #onSuccess(): void {
    this.#consecutiveFailures = 0;
    if (this.#state === "half_open") {
      this.#transition("closed", "probe_succeeded");
    }
  }

  #onFailure(now: Date): void {
    this.#consecutiveFailures++;
    if (this.#state === "half_open") {
      // The trial call failed — back to fully open, and the cooldown
      // restarts from now rather than continuing to count from the
      // original trip.
      this.#openedAt = now.getTime();
      this.#transition("open", "probe_failed");
      return;
    }
    if (this.#state === "closed" && this.#consecutiveFailures >= this.#config.failureThreshold) {
      this.#openedAt = now.getTime();
      this.#transition("open", "failure_threshold_reached");
    }
  }

  #transition(to: CircuitState, reason: CircuitTransitionReason): void {
    const from = this.#state;
    this.#state = to;
    this.#onStateChange?.({ from, to, reason });
  }
}
