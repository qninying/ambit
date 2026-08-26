// REQ-016: detect anomalies in token requests and alert — this is a signal,
// not a gate. An anomalous request still goes through the normal consent
// flow (STORY-003); nothing here blocks it. Two real, explainable signals
// rather than a stub that's always true or always false:
//
//  - scope breadth: a single request asking for more than the threshold is
//    unusually broad for one credential.
//  - velocity: the same subject submitting more than the threshold within a
//    short window is unusual — tracked per-subject, so one agent's burst
//    can't flag an unrelated one.
//
// Thresholds are a judgment call, not derived from any spec — configurable
// here in one place (constructor + env vars in server.ts) rather than
// hardcoded, so a wrong guess is a one-line/env-var fix, not a code change.

export interface AnomalyDetectorConfig {
  maxScopeBreadth: number;
  velocityWindowMs: number;
  maxRequestsPerWindow: number;
}

export const DEFAULT_ANOMALY_CONFIG: AnomalyDetectorConfig = {
  maxScopeBreadth: 3,
  velocityWindowMs: 60_000,
  maxRequestsPerWindow: 3,
};

export interface AnomalyResult {
  anomalous: boolean;
  signals: string[];
}

export class AnomalyDetector {
  #config: AnomalyDetectorConfig;
  #recentBySubject = new Map<string, Date[]>();

  constructor(config: Partial<AnomalyDetectorConfig> = {}) {
    // `??`, not spread — a partial config with an explicit `undefined` (e.g.
    // an unset env var parsed to undefined) must still fall back to the
    // default, not silently become undefined itself.
    this.#config = {
      maxScopeBreadth: config.maxScopeBreadth ?? DEFAULT_ANOMALY_CONFIG.maxScopeBreadth,
      velocityWindowMs: config.velocityWindowMs ?? DEFAULT_ANOMALY_CONFIG.velocityWindowMs,
      maxRequestsPerWindow: config.maxRequestsPerWindow ?? DEFAULT_ANOMALY_CONFIG.maxRequestsPerWindow,
    };
  }

  check(subject: string, scope: string[], now: Date = new Date()): AnomalyResult {
    const signals: string[] = [];

    if (scope.length > this.#config.maxScopeBreadth) {
      signals.push("scope_too_broad");
    }

    const recent = (this.#recentBySubject.get(subject) ?? []).filter(
      (t) => now.getTime() - t.getTime() < this.#config.velocityWindowMs,
    );
    recent.push(now);
    this.#recentBySubject.set(subject, recent);
    if (recent.length > this.#config.maxRequestsPerWindow) {
      signals.push("high_velocity");
    }

    return { anomalous: signals.length > 0, signals };
  }
}
