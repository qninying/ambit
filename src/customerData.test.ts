import { describe, expect, it } from "vitest";
import { CustomerDataRegistry, DEFAULT_SEED_CUSTOMERS } from "./customerData.js";

describe("CustomerDataRegistry", () => {
  it("returns a seeded customer record by id", () => {
    const registry = new CustomerDataRegistry();
    const customer = registry.get("cust-001");

    expect(customer?.id).toBe("cust-001");
    expect(customer?.name).toBeTruthy();
  });

  it("returns undefined for an unknown customer id", () => {
    const registry = new CustomerDataRegistry();
    expect(registry.get("not-a-real-customer")).toBeUndefined();
  });

  it("accepts a custom seed instead of the default one", () => {
    const custom = [{ id: "x-1", name: "Test User", email: "t@example.com", phone: "555-0000", ssn: "000-00-0000", address: "1 Test Way" }];
    const registry = new CustomerDataRegistry(custom);

    expect(registry.get("x-1")).toEqual(custom[0]);
    expect(registry.get(DEFAULT_SEED_CUSTOMERS[0]!.id)).toBeUndefined();
  });
});
