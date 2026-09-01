import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appendJsonLine, rehydrateJsonLines } from "./jsonlStore.js";

let dir: string;
let file: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ambit-jsonl-test-"));
  file = join(dir, "nested", "store.jsonl");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("appendJsonLine", () => {
  it("creates the parent directory if it doesn't exist yet", () => {
    expect(existsSync(file)).toBe(false);
    appendJsonLine(file, { a: 1 });
    expect(existsSync(file)).toBe(true);
  });

  it("appends one JSON object per line, in call order", () => {
    appendJsonLine(file, { n: 1 });
    appendJsonLine(file, { n: 2 });
    const lines = readFileSync(file, "utf-8").trim().split("\n");
    expect(lines.map((l) => JSON.parse(l))).toEqual([{ n: 1 }, { n: 2 }]);
  });
});

describe("rehydrateJsonLines", () => {
  it("returns an empty array when the file doesn't exist — a fresh store, not an error", () => {
    expect(rehydrateJsonLines(file, (raw) => raw)).toEqual([]);
  });

  it("replays every line through revive, in file order", () => {
    appendJsonLine(file, { n: 1 });
    appendJsonLine(file, { n: 2 });
    appendJsonLine(file, { n: 3 });
    const revived = rehydrateJsonLines(file, (raw) => (raw as { n: number }).n);
    expect(revived).toEqual([1, 2, 3]);
  });

  // Matches CoreOps's ADR-005: the likely real-world cause is one truncated
  // final line from a crash mid-append — refusing to start over one bad
  // line would be a worse failure mode than losing just that entry.
  it("skips a corrupted line (not valid JSON) and still returns every valid one, with a warning", () => {
    appendJsonLine(file, { n: 1 });
    appendFileSync(file, "{not valid json\n");
    appendJsonLine(file, { n: 2 });

    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const revived = rehydrateJsonLines(file, (raw) => (raw as { n: number }).n);
    expect(revived).toEqual([1, 2]);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });

  it("skips a line that fails the caller's own revive() validation, not just JSON parsing", () => {
    appendJsonLine(file, { n: 1 });
    appendJsonLine(file, { n: "not-a-number" });

    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const revived = rehydrateJsonLines(file, (raw) => {
      const n = (raw as { n: unknown }).n;
      if (typeof n !== "number") throw new Error("n must be a number");
      return n;
    });
    expect(revived).toEqual([1]);
    warnSpy.mockRestore();
  });

  it("ignores trailing blank lines", () => {
    appendJsonLine(file, { n: 1 });
    appendFileSync(file, "\n\n");
    expect(rehydrateJsonLines(file, (raw) => raw)).toEqual([{ n: 1 }]);
  });
});
