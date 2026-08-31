// Pure formatting/escaping helpers + inline icon set. Zero internal
// dependencies — every other module can safely import from here.

export function esc(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

export function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function relTime(iso) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const s = Math.round(diffMs / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function tokenStatusBadge(token, now = new Date()) {
  if (token.status === "revoked") return `<span class="badge badge-danger"><span class="dot"></span>Revoked</span>`;
  if (new Date(token.expiresAt).getTime() <= now.getTime()) return `<span class="badge badge-neutral"><span class="dot"></span>Expired</span>`;
  return `<span class="badge badge-ok"><span class="dot"></span>Active</span>`;
}

const DECISION_MAP = {
  allowed: ["badge-ok", "Allowed"],
  denied: ["badge-danger", "Denied"],
  revoked: ["badge-danger", "Revoked"],
  request_submitted: ["badge-neutral", "Submitted"],
  request_approved: ["badge-ok", "Approved"],
  request_denied: ["badge-danger", "Denied"],
  anomaly_detected: ["badge-warn", "Anomaly"],
  policy_created: ["badge-accent", "Policy created"],
  policy_modified: ["badge-accent", "Policy modified"],
  circuit_opened: ["badge-danger", "Circuit opened"],
  circuit_closed: ["badge-ok", "Circuit closed"],
  redaction_rule_created: ["badge-accent", "Rule created"],
  data_accessed: ["badge-ok", "Data accessed"],
};

export function decisionBadge(entry) {
  const [cls, label] = DECISION_MAP[entry.decision] || ["badge-neutral", entry.decision];
  return `<span class="badge ${cls}"><span class="dot"></span>${esc(label)}</span>`;
}

export function scopeTags(scope) {
  return scope.map((s) => `<span class="tag">${esc(s)}</span>`).join("");
}

// Deterministic 1-2 letter avatar initials from a free-text subject string.
export function initials(subject) {
  const parts = String(subject || "?").trim().split(/[\s\-_.]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

export function hashParam() {
  // "#tokens/<id>" -> "<id>"
  const parts = (location.hash || "").slice(1).split("/");
  return parts[1] || null;
}

// ---------- icon set (inline SVG, no icon-font dependency) ----------

export function iconGrid() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="9" y="1.5" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="9" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="9" y="9" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/></svg>`;
}
export function iconInbox() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M1.5 8.5h3.6l1 2h3.8l1-2h3.6" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M2.3 4.5 1.5 8.8v3.7a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V8.8l-.8-4.3a1 1 0 0 0-1-.8H3.3a1 1 0 0 0-1 .8Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
export function iconKey() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="5.5" cy="9.5" r="3.3" stroke="currentColor" stroke-width="1.4"/><path d="M7.7 7.3 13.5 1.5M11.5 3.5l1.5 1.5M9.5 5.5 11 7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
}
export function iconShield() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 1.5 13.5 3.5V7.5C13.5 11 11.2 13.3 8 14.5C4.8 13.3 2.5 11 2.5 7.5V3.5L8 1.5Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
export function iconRedact() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="1.5" y="4.5" width="13" height="7" rx="1.4" stroke="currentColor" stroke-width="1.4"/><path d="M4 8h2.4M8 8h2.4M4.8 6.3h1.2M9.6 6.3h1.2M4.8 9.7h1.2M9.6 9.7h1.2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`;
}
export function iconList() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M5 3h9M5 8h9M5 13h9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><circle cx="1.8" cy="3" r="1" fill="currentColor"/><circle cx="1.8" cy="8" r="1" fill="currentColor"/><circle cx="1.8" cy="13" r="1" fill="currentColor"/></svg>`;
}
export function iconPulse() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M1.5 8.5h3l1.5-4 2.5 7 1.5-3h4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}
export function iconSun() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.4"/><path d="M8 1.3v1.6M8 13.1v1.6M2.5 8H1M15 8h-1.5M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`;
}
export function iconMoon() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M13.7 9.9A5.6 5.6 0 1 1 6.1 2.3a5.6 5.6 0 0 0 7.6 7.6Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
export function iconChevronRight() {
  return `<svg width="11" height="11" viewBox="0 0 16 16" fill="none"><path d="M6 3.5 11 8l-5 4.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}
export function iconLink() {
  return `<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M6.8 9.2 9.2 6.8M6.5 4.5 8 3a2.6 2.6 0 0 1 3.7 3.7L10.2 8.2M9.5 11.5 8 13a2.6 2.6 0 0 1-3.7-3.7L5.8 7.8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
}
export function iconAlert() {
  return `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2 14.5 13.5H1.5L8 2Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.4v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
}
