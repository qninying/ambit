// REQ-009: field-level redaction needs something to redact. Ambit's own
// domain has never had a "customer" concept before this story — this is a
// small, deterministic, in-memory dataset, same treatment as STORY-005's
// MockEndpointRegistry: real enough to demo the real mechanism against,
// clearly not a production customer database.

export interface CustomerRecord {
  id: string;
  name: string;
  email: string;
  phone: string;
  ssn: string;
  address: string;
}

export class CustomerDataRegistry {
  #customers = new Map<string, CustomerRecord>();

  constructor(seed: CustomerRecord[] = DEFAULT_SEED_CUSTOMERS) {
    for (const customer of seed) {
      this.#customers.set(customer.id, customer);
    }
  }

  get(id: string): CustomerRecord | undefined {
    return this.#customers.get(id);
  }
}

// Fixed, deterministic seed data — not randomly generated — so a test or a
// demo run always sees the same records.
export const DEFAULT_SEED_CUSTOMERS: CustomerRecord[] = [
  {
    id: "cust-001",
    name: "Jordan Ellis",
    email: "jordan.ellis@example.com",
    phone: "555-0101",
    ssn: "123-45-6789",
    address: "12 Birch Street, Springfield",
  },
  {
    id: "cust-002",
    name: "Priya Nair",
    email: "priya.nair@example.com",
    phone: "555-0102",
    ssn: "987-65-4321",
    address: "48 Maple Avenue, Riverton",
  },
];
