// REQ-007: mock endpoints for email, code hosting, payment, and CRM systems.
// These simulate real downstream calls rather than literally reaching an
// external service (no real credentials to do that with) — but the failure
// mode is real and deterministic, not random, so "endpoint is unreachable"
// is something a test can actually exercise on purpose.

export type MockSystem = "email" | "code-hosting" | "payment" | "crm";

export interface MockEndpointResult {
  system: MockSystem;
  verb: string;
  detail: string;
}

export class EndpointUnreachableError extends Error {
  constructor(system: MockSystem) {
    super(`${system} endpoint is unreachable`);
    this.name = "EndpointUnreachableError";
  }
}

export class MockEndpointRegistry {
  #down = new Set<MockSystem>();

  // Deterministic, not random — a test (or a demo) can put a specific system
  // into a known-bad state and get a predictable result back.
  setDown(system: MockSystem, down: boolean): void {
    if (down) this.#down.add(system);
    else this.#down.delete(system);
  }

  async call(system: MockSystem, verb: string): Promise<MockEndpointResult> {
    if (this.#down.has(system)) {
      throw new EndpointUnreachableError(system);
    }
    // Small simulated latency — real enough to exercise the timeout wrapper
    // around this in mockEndpointAccess.ts without slowing tests down.
    await new Promise((resolve) => setTimeout(resolve, 5));
    return { system, verb, detail: `${system}:${verb} succeeded` };
  }
}
