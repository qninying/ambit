import { describe, expect, it } from "vitest";
import { EndpointUnreachableError, MockEndpointRegistry } from "./mockEndpoints.js";

describe("MockEndpointRegistry", () => {
  it("succeeds for a system that's up", async () => {
    const registry = new MockEndpointRegistry();
    const result = await registry.call("email", "send");
    expect(result).toEqual({ system: "email", verb: "send", detail: "email:send succeeded" });
  });

  it("throws EndpointUnreachableError once a system is marked down", async () => {
    const registry = new MockEndpointRegistry();
    registry.setDown("payment", true);
    await expect(registry.call("payment", "charge")).rejects.toThrow(EndpointUnreachableError);
  });

  it("only affects the system that was marked down, not the others", async () => {
    const registry = new MockEndpointRegistry();
    registry.setDown("payment", true);
    const result = await registry.call("email", "send");
    expect(result.system).toBe("email");
  });

  it("recovers once marked back up", async () => {
    const registry = new MockEndpointRegistry();
    registry.setDown("crm", true);
    registry.setDown("crm", false);
    const result = await registry.call("crm", "read");
    expect(result.system).toBe("crm");
  });
});
