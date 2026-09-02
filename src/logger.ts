// ADR-020: closes the INPACT Transparency dimension's remaining named gap
// — the hash-chained audit log (ADR-008) captures every *domain* event
// (approvals, denials, revocations), but nothing structured captured
// *operational* events outside it. Before this, three real call sites
// logged a bare, unstructured string or error object — nothing to grep,
// filter, or alert on. Ported from CoreOps's own observability/logger.ts,
// scaled down: no stderr deviation, since that exists there specifically
// because CoreOps's MCP stdio transport reserves stdout for the JSON-RPC
// protocol stream — Ambit has no MCP server (a deliberate decision, not an
// oversight) and no such constraint, so plain stdout is correct here.

export type LogLevel = "info" | "warn" | "error";

export interface LogEventInput {
  level: LogLevel;
  event: string;
  context?: Record<string, unknown>;
}

export function logEvent(input: LogEventInput): void {
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    level: input.level,
    service: "ambit",
    event: input.event,
    context: input.context ?? {},
  });
  console.log(line);
}
