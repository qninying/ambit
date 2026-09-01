// ADR-014: the shared mechanics behind every store's optional persistence —
// append-only JSONL, one JSON object per line, rehydrate-on-start. Same
// shape CoreOps's own ADR-005 established for its audit trail; here every
// store gets it (ADR-006 named this as the graduation path from day one,
// not something invented now), so the mechanics are lifted into one shared
// module instead of reimplemented per store.

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

export function appendJsonLine(filePath: string, value: unknown): void {
  mkdirSync(dirname(filePath), { recursive: true });
  appendFileSync(filePath, `${JSON.stringify(value)}\n`);
}

// Callers here are "current state by id" stores (save() can overwrite an
// existing id — a revoked token, a modified policy). Replaying every line
// in file order through the caller's own Map.set()-based save() naturally
// makes a later line for the same id supersede an earlier one, the exact
// same last-write-wins semantics save() already has in memory — no special
// "is this an update" logic needed here. A line that fails to parse or
// fails `revive` is skipped with a loud console.error, not a fatal startup
// error, matching CoreOps's ADR-005: the likely cause is one truncated
// final line from a crash mid-append, and refusing to start over one bad
// line is a worse failure mode than losing just that entry.
export function rehydrateJsonLines<T>(filePath: string, revive: (raw: unknown) => T): T[] {
  if (!existsSync(filePath)) return [];
  const lines = readFileSync(filePath, "utf-8").split("\n").filter((line) => line.trim().length > 0);
  const results: T[] = [];
  for (const [index, line] of lines.entries()) {
    try {
      results.push(revive(JSON.parse(line)));
    } catch (err) {
      console.error(`${filePath}: skipping corrupted line ${index + 1} — ${(err as Error).message}`);
    }
  }
  return results;
}
