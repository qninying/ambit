// Data layer: fetch helpers, the polled STATE snapshot, and the two guards
// that keep background polling from clobbering an operator's work. Owns no
// rendering and no routing — app.js is what ties this to render().

import { getSessionToken, clearSessionToken } from "./auth.js";

export const POLL_MS = 4000;

// Exported as a live binding (never destructure this into a local — that
// captures a stale snapshot). refreshAll() reassigns the whole object, and
// every importer sees the current value via ES module live bindings.
export let STATE = {
  requests: [],
  tokens: [],
  policies: [],
  auditLog: [],
  redactionRules: [],
  circuitBreaker: { state: "closed" },
  lastFetchedAt: null,
};

// True while a create/edit form is open (Policies/Redaction Rules tabs) — a
// background poll re-render would otherwise wipe it out even before the
// operator has typed anything, since every render function rebuilds its
// tab's DOM from scratch.
let formOpenFlag = false;
export function isFormOpen() { return formOpenFlag; }
export function setFormOpen(value) { formOpenFlag = value; }

export async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

// ADR-011: attaches the session token (if any) to every POST — harmless on
// routes that don't require one (most of the API still doesn't), and the
// one thing approve/deny actually need. A 401 means the session is no
// longer valid (expired, or signed with a secret that's since rotated) —
// clear it so the UI asks to log in again instead of silently retrying
// with a token that will never work.
export async function postJson(path, body, extraHeaders) {
  const token = getSessionToken();
  const headers = { "Content-Type": "application/json", ...(extraHeaders || {}) };
  if (token && !headers.Authorization) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) clearSessionToken();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ADR-015: same session-attachment/401-clearing treatment as postJson —
// PATCH /policies/:id now requires one too. This had silently never
// attached a session token at all before, harmless while nothing PATCH-based
// required one; a real gap once something did.
export async function patchJson(path, body) {
  const token = getSessionToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { method: "PATCH", headers, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) clearSessionToken();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

let lastDataFingerprint = null;

// Returns true if the fetched data actually differs from what's already
// rendered. A poll that finds nothing new shouldn't rebuild the DOM at all —
// that's needless flicker on every idle tick, and it's exactly what turns a
// background refresh into something that can clip an in-flight click.
export async function refreshAll() {
  const [requests, tokens, policies, auditLog, redactionRules, circuitBreaker] = await Promise.all([
    fetchJson("/requests"),
    fetchJson("/tokens"),
    fetchJson("/policies"),
    fetchJson("/audit-log"),
    fetchJson("/redaction-rules"),
    fetchJson("/circuit-breaker"),
  ]);
  const fingerprint = JSON.stringify({ requests, tokens, policies, auditLog, redactionRules, circuitBreaker });
  const changed = fingerprint !== lastDataFingerprint;
  lastDataFingerprint = fingerprint;
  STATE = { requests, tokens, policies, auditLog, redactionRules, circuitBreaker, lastFetchedAt: new Date() };
  return changed;
}

// A background poll tick fully re-renders the current tab from scratch. If
// that fires while an operator is mid-typing in any form (new/edit policy,
// submit request, delegate, etc.), it would silently wipe out their input
// from under them — a live-refreshing console must never do that. So: still
// refresh the underlying data (nothing goes stale for when they're done),
// but skip the destructive re-render while any field inside the tab content
// has focus.
export function formFieldIsFocused() {
  const active = document.activeElement;
  const tabContent = document.getElementById("tab-content");
  return !!(active && tabContent && tabContent.contains(active) && ["INPUT", "SELECT", "TEXTAREA"].includes(active.tagName));
}
