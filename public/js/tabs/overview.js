import { STATE } from "../state.js";
import { esc, relTime, decisionBadge } from "../format.js";

const FEED_ICONS = {
  allowed: ["var(--success-bg)", "var(--success)", "✓"],
  denied: ["var(--danger-bg)", "var(--danger)", "✕"],
  revoked: ["var(--danger-bg)", "var(--danger)", "⊘"],
  request_approved: ["var(--success-bg)", "var(--success)", "✓"],
  request_denied: ["var(--danger-bg)", "var(--danger)", "✕"],
  anomaly_detected: ["var(--warning-bg)", "var(--warning)", "!"],
  policy_created: ["var(--accent-soft)", "var(--accent-text)", "+"],
  policy_modified: ["var(--accent-soft)", "var(--accent-text)", "~"],
  circuit_opened: ["var(--danger-bg)", "var(--danger)", "⚡"],
  circuit_closed: ["var(--success-bg)", "var(--success)", "✓"],
  redaction_rule_created: ["var(--accent-soft)", "var(--accent-text)", "+"],
  data_accessed: ["var(--success-bg)", "var(--success)", "◐"],
};

// 12 real hourly buckets of audit-log volume — no fabricated series. This
// is the one chart in the app; it earns its place by answering "is activity
// picking up or quiet right now" faster than scanning the feed below it.
function activitySparkline() {
  const buckets = new Array(12).fill(0);
  const now = Date.now();
  for (const e of STATE.auditLog) {
    const ageMs = now - new Date(e.occurredAt).getTime();
    const idx = 11 - Math.floor(ageMs / (60 * 60 * 1000));
    if (idx >= 0 && idx < 12) buckets[idx] += 1;
  }
  const max = Math.max(1, ...buckets);
  return `<div class="sparkline-row" role="img" aria-label="Audit activity over the last 12 hours">
    ${buckets.map((n) => `<div class="sparkline-bar${n > 0 ? " has-activity" : ""}" style="height:${Math.max(3, Math.round((n / max) * 26))}px" title="${n} event${n === 1 ? "" : "s"}"></div>`).join("")}
  </div>`;
}

export function renderOverview(main) {
  const now = new Date();
  const activeTokens = STATE.tokens.filter((t) => t.status === "active" && new Date(t.expiresAt).getTime() > now.getTime());
  const revokedTokens = STATE.tokens.filter((t) => t.status === "revoked");
  const breakerState = STATE.circuitBreaker?.state || "closed";

  const recent = [...STATE.auditLog].slice(-8).reverse();

  main.innerHTML = `
    <div class="metrics-strip">
      <div class="metric">
        <div class="metric-label">Pending Requests</div>
        <div class="metric-value">${STATE.requests.length}</div>
        <div class="metric-hint">awaiting a human decision</div>
      </div>
      <div class="metric">
        <div class="metric-label">Active Tokens</div>
        <div class="metric-value">${activeTokens.length}</div>
        <div class="metric-hint">of ${STATE.tokens.length} ever issued</div>
      </div>
      <div class="metric">
        <div class="metric-label">Revoked Tokens</div>
        <div class="metric-value">${revokedTokens.length}</div>
        <div class="metric-hint">manually or cascaded</div>
      </div>
      <div class="metric">
        <div class="metric-label">Policies Defined</div>
        <div class="metric-value">${STATE.policies.length}</div>
        <div class="metric-hint">governing scope &amp; TTL</div>
      </div>
      <div class="metric">
        <div class="metric-label">Store Health</div>
        <div class="metric-value" style="font-size:17px; text-transform:capitalize;">${esc(breakerState.replace("_", "-"))}</div>
        <div class="metric-hint">circuit breaker</div>
      </div>
      <div class="metric">
        <div class="metric-label">Activity — last 12h</div>
        ${activitySparkline()}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Recent activity</h3><span class="panel-meta">${STATE.auditLog.length} total entries</span></div>
      <div class="panel-body">
        ${recent.length === 0
          ? `<div class="empty-state"><div class="empty-title">Nothing has happened yet</div>Submit a request from the Requests tab to see activity here.</div>`
          : recent.map((e) => {
              const [bg, color, glyph] = FEED_ICONS[e.decision] || ["var(--surface-sunken)", "var(--text-secondary)", "•"];
              return `<div class="feed-item">
                <div class="feed-icon" style="background:${bg};color:${color};">${glyph}</div>
                <div class="feed-text"><strong>${esc(e.subject)}</strong> — ${esc(e.action)} ${decisionBadge(e)}${e.reasonCode ? ` <span class="text-tertiary">(${esc(e.reasonCode)})</span>` : ""}</div>
                <div class="feed-time">${relTime(e.occurredAt)}</div>
              </div>`;
            }).join("")}
      </div>
    </div>
  `;
}
