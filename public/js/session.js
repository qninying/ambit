// "Acting as" — the operator identity string the console sends as
// `approver`/`authoredBy` on write calls. Ambit has no authentication (see
// ADR-009): this is the same free-text field the backend already accepts,
// made visible and editable instead of hardcoded per call site. Persisted
// as a genuine preference (localStorage), unlike a secret.

const KEY = "ambit.actingAs";
const DEFAULT_NAME = "operator";

export function actingAs() {
  try {
    return localStorage.getItem(KEY) || DEFAULT_NAME;
  } catch {
    return DEFAULT_NAME;
  }
}

export function setActingAs(name) {
  const trimmed = String(name || "").trim();
  try {
    if (trimmed) localStorage.setItem(KEY, trimmed);
    else localStorage.removeItem(KEY);
  } catch {
    // localStorage unavailable (private mode, blocked) — falls back to
    // DEFAULT_NAME on next read, not a functional failure.
  }
}
