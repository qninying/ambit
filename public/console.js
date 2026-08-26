// Ambit Console — shared runtime for the single-page tabbed admin app.
// Everything here fetches from the real server at runtime; there is no
// sample/illustrative mode, unlike the Command Center — this console IS the
// live application, so every number on it is real by construction.

const TABS = [
  { id: "overview", label: "Overview", icon: iconGrid },
  { id: "requests", label: "Requests", icon: iconInbox, badgeKey: "pendingCount" },
  { id: "tokens", label: "Tokens", icon: iconKey },
  { id: "policies", label: "Policies", icon: iconShield },
  { id: "audit", label: "Audit Log", icon: iconList },
];

const POLL_MS = 4000;

let STATE = {
  requests: [],
  tokens: [],
  policies: [],
  auditLog: [],
  lastFetchedAt: null,
};

// True while a create/edit form is open (Policies tab) — a background poll
// re-render would otherwise wipe it out even before the operator has typed
// anything, since renderPolicies() rebuilds the form slot from scratch.
let formOpen = false;

// ---------- tiny icon set (inline, no icon-font dependency) ----------

function iconGrid() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="9" y="1.5" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="9" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/><rect x="9" y="9" width="5.5" height="5.5" rx="1.2" stroke="currentColor" stroke-width="1.4"/></svg>`;
}
function iconInbox() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M1.5 8.5h3.6l1 2h3.8l1-2h3.6" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M2.3 4.5 1.5 8.8v3.7a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V8.8l-.8-4.3a1 1 0 0 0-1-.8H3.3a1 1 0 0 0-1 .8Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
function iconKey() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="5.5" cy="9.5" r="3.3" stroke="currentColor" stroke-width="1.4"/><path d="M7.7 7.3 13.5 1.5M11.5 3.5l1.5 1.5M9.5 5.5 11 7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
}
function iconShield() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 1.5 13.5 3.5V7.5C13.5 11 11.2 13.3 8 14.5C4.8 13.3 2.5 11 2.5 7.5V3.5L8 1.5Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
function iconList() {
  return `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M5 3h9M5 8h9M5 13h9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><circle cx="1.8" cy="3" r="1" fill="currentColor"/><circle cx="1.8" cy="8" r="1" fill="currentColor"/><circle cx="1.8" cy="13" r="1" fill="currentColor"/></svg>`;
}

// ---------- data layer ----------

async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

async function postJson(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function patchJson(path, body) {
  const res = await fetch(path, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

let lastDataFingerprint = null;

// Returns true if the fetched data actually differs from what's already
// rendered. A poll that finds nothing new shouldn't rebuild the DOM at all —
// that's needless flicker on every idle tick, and it's exactly what turns a
// background refresh into something that can clip an in-flight click.
async function refreshAll() {
  const [requests, tokens, policies, auditLog] = await Promise.all([
    fetchJson("/requests"),
    fetchJson("/tokens"),
    fetchJson("/policies"),
    fetchJson("/audit-log"),
  ]);
  const fingerprint = JSON.stringify({ requests, tokens, policies, auditLog });
  const changed = fingerprint !== lastDataFingerprint;
  lastDataFingerprint = fingerprint;
  STATE = { requests, tokens, policies, auditLog, lastFetchedAt: new Date() };
  return changed;
}

// ---------- helpers ----------

function esc(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function relTime(iso) {
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

function tokenStatusBadge(token, now = new Date()) {
  if (token.status === "revoked") return `<span class="badge badge-danger"><span class="dot"></span>Revoked</span>`;
  if (new Date(token.expiresAt).getTime() <= now.getTime()) return `<span class="badge badge-neutral"><span class="dot"></span>Expired</span>`;
  return `<span class="badge badge-ok"><span class="dot"></span>Active</span>`;
}

function decisionBadge(entry) {
  const map = {
    allowed: ["badge-ok", "Allowed"],
    denied: ["badge-danger", "Denied"],
    revoked: ["badge-danger", "Revoked"],
    request_approved: ["badge-ok", "Approved"],
    request_denied: ["badge-danger", "Denied"],
    anomaly_detected: ["badge-warn", "Anomaly"],
    policy_created: ["badge-accent", "Policy created"],
    policy_modified: ["badge-accent", "Policy modified"],
  };
  const [cls, label] = map[entry.decision] || ["badge-neutral", entry.decision];
  return `<span class="badge ${cls}"><span class="dot"></span>${esc(label)}</span>`;
}

function scopeTags(scope) {
  return scope.map((s) => `<span class="tag">${esc(s)}</span>`).join("");
}

function hashParam() {
  // "#tokens/<id>" -> "<id>"
  const parts = (location.hash || "").slice(1).split("/");
  return parts[1] || null;
}

// ---------- Overview ----------

function renderOverview(main) {
  const now = new Date();
  const activeTokens = STATE.tokens.filter((t) => t.status === "active" && new Date(t.expiresAt).getTime() > now.getTime());
  const revokedTokens = STATE.tokens.filter((t) => t.status === "revoked");

  const recent = [...STATE.auditLog].slice(-8).reverse();
  const feedIcons = {
    allowed: ["#ecfdf3", "#15803d", "✓"], denied: ["#fef2f2", "#b91c1c", "✕"], revoked: ["#fef2f2", "#b91c1c", "⊘"],
    request_approved: ["#ecfdf3", "#15803d", "✓"], request_denied: ["#fef2f2", "#b91c1c", "✕"],
    anomaly_detected: ["#fffaeb", "#b45309", "!"], policy_created: ["#eef0fd", "#4338ca", "+"], policy_modified: ["#eef0fd", "#4338ca", "~"],
  };

  main.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-label">Pending Requests</div><div class="stat-value">${STATE.requests.length}</div><div class="stat-hint">awaiting a human decision</div></div>
      <div class="stat-card"><div class="stat-label">Active Tokens</div><div class="stat-value">${activeTokens.length}</div><div class="stat-hint">of ${STATE.tokens.length} ever issued</div></div>
      <div class="stat-card"><div class="stat-label">Revoked Tokens</div><div class="stat-value">${revokedTokens.length}</div><div class="stat-hint">manually or cascaded</div></div>
      <div class="stat-card"><div class="stat-label">Policies Defined</div><div class="stat-value">${STATE.policies.length}</div><div class="stat-hint">governing scope &amp; TTL</div></div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Recent activity</h3><span style="font-size:12px;color:var(--muted-weak);">${STATE.auditLog.length} total entries</span></div>
      <div class="panel-body">
        ${recent.length === 0
          ? `<div class="empty-state"><div class="empty-title">Nothing has happened yet</div>Submit a request from the Requests tab to see activity here.</div>`
          : recent.map((e) => {
              const [bg, color, glyph] = feedIcons[e.decision] || ["#f1f2f5", "#6b7280", "•"];
              return `<div class="feed-item">
                <div class="feed-icon" style="background:${bg};color:${color};">${glyph}</div>
                <div class="feed-text"><strong>${esc(e.subject)}</strong> — ${esc(e.action)} ${decisionBadge(e)}${e.reasonCode ? ` <span style="color:var(--muted-weak);">(${esc(e.reasonCode)})</span>` : ""}</div>
                <div class="feed-time">${relTime(e.occurredAt)}</div>
              </div>`;
            }).join("")}
      </div>
    </div>
  `;
}

// ---------- Requests (Consent) ----------

function renderRequests(main) {
  const list = STATE.requests;
  main.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h3>Pending requests</h3></div>
      <div class="panel-body padded" id="requests-list"></div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Submit a test request</h3></div>
      <div class="panel-body padded">
        <p class="page-desc" style="margin:0 0 12px;">Stands in for the client SDK (not built yet) — a real agent would submit this programmatically.</p>
        <div class="form-row">
          <div class="field"><label>Subject</label><input id="req-subject" placeholder="agent-42" /></div>
          <div class="field"><label>Scope (comma-separated)</label><input id="req-scope" placeholder="email:send, crm:read" /></div>
        </div>
        <div class="form-row">
          <div class="field"><label>TTL (seconds)</label><input id="req-ttl" placeholder="300" /></div>
          <div class="field"><label>Policy (optional)</label>
            <select id="req-policy"><option value="">— none —</option>${STATE.policies.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select>
          </div>
        </div>
        <button class="btn btn-primary" id="req-submit">Submit request</button>
        <div class="toast" id="req-toast"></div>
      </div>
    </div>
  `;

  const listEl = document.getElementById("requests-list");
  if (list.length === 0) {
    listEl.innerHTML = `<div class="empty-state"><div class="empty-title">No pending requests</div>Every request waits here until an approver acts on it.</div>`;
  } else {
    listEl.innerHTML = list.map((r) => `
      <div class="panel" style="margin:0 0 12px; box-shadow:none;" data-id="${r.id}">
        <div class="panel-body padded">
          <div style="font-weight:700; font-size:14px; margin-bottom:2px;">${esc(r.subject)}</div>
          <div style="font-size:13px; color:var(--text); margin-bottom:8px;">Requesting ${scopeTags(r.scope)} — valid ${r.ttlSeconds}s if approved${r.policyId ? ` <span class="badge badge-accent">policy attached</span>` : ""}</div>
          <div style="font-size:11.5px; color:var(--muted-weak); margin-bottom:10px;">Requested ${fmtTime(r.requestedAt)}</div>
          <button class="btn btn-ok btn-sm" data-action="approve" data-id="${r.id}">Approve</button>
          <button class="btn btn-danger btn-sm" data-action="deny" data-id="${r.id}">Deny</button>
          <div class="toast" data-toast-for="${r.id}"></div>
        </div>
      </div>
    `).join("");
    listEl.querySelectorAll("button[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => decideRequest(btn.dataset.id, btn.dataset.action));
    });
  }

  document.getElementById("req-submit").addEventListener("click", submitTestRequest);
}

async function decideRequest(id, action) {
  const card = document.querySelector(`[data-id="${id}"]`);
  const toast = card.querySelector(`[data-toast-for="${id}"]`);
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    const body = { approver: "demo-approver" };
    if (action === "deny") body.reasonCode = "declined_by_approver";
    await postJson(`/requests/${id}/${action}`, body);
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    card.querySelectorAll("button").forEach((b) => (b.disabled = false));
    return;
  }
  await tick(true);
}

async function submitTestRequest() {
  const subject = document.getElementById("req-subject").value.trim();
  const scope = document.getElementById("req-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttlSeconds = Number(document.getElementById("req-ttl").value);
  const policyId = document.getElementById("req-policy").value || undefined;
  const toast = document.getElementById("req-toast");
  try {
    await postJson("/requests", { subject, scope, ttlSeconds, policyId });
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  toast.textContent = "Request submitted.";
  toast.className = "toast ok";
  await tick(true);
}

// ---------- Tokens ----------

function renderTokens(main) {
  const id = hashParam();
  if (id) return renderTokenDetail(main, id);

  main.innerHTML = `
    <div class="panel">
      <div class="panel-body">
        ${STATE.tokens.length === 0
          ? `<div class="empty-state"><div class="empty-title">No tokens issued yet</div>Approve a request to issue the first one.</div>`
          : `<table class="data-table"><thead><tr><th>Subject</th><th>Scope</th><th>Status</th><th>Issued</th><th>Expires</th><th>Lineage</th></tr></thead>
             <tbody>${[...STATE.tokens].reverse().map((t) => `
               <tr class="clickable" data-id="${t.id}">
                 <td>${esc(t.subject)}</td>
                 <td>${scopeTags(t.scope)}</td>
                 <td>${tokenStatusBadge(t)}</td>
                 <td>${fmtTime(t.issuedAt)}</td>
                 <td>${fmtTime(t.expiresAt)}</td>
                 <td>${t.parentTokenId ? `<span class="badge badge-accent">delegated</span>` : `<span class="badge badge-neutral">root</span>`}</td>
               </tr>
             `).join("")}</tbody></table>`}
      </div>
    </div>
  `;
  main.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", () => { location.hash = `#tokens/${row.dataset.id}`; });
  });
}

function renderTokenDetail(main, id) {
  const token = STATE.tokens.find((t) => t.id === id);
  if (!token) {
    main.innerHTML = `<a class="back-link" href="#tokens">← Tokens</a><div class="empty-state">No token "${esc(id)}" found.</div>`;
    return;
  }
  const parent = token.parentTokenId ? STATE.tokens.find((t) => t.id === token.parentTokenId) : null;
  const children = STATE.tokens.filter((t) => t.parentTokenId === token.id);
  const canRevoke = token.status === "active";

  main.innerHTML = `
    <a class="back-link" href="#tokens">← Tokens</a>
    <div class="panel">
      <div class="panel-header">
        <h3>${esc(token.subject)} ${tokenStatusBadge(token)}</h3>
        ${canRevoke ? `<button class="btn btn-danger btn-sm" id="revoke-btn">Revoke</button>` : ""}
      </div>
      <div class="panel-body padded">
        <div class="detail-grid">
          <div class="detail-field"><div class="field-label">Token ID</div><div class="field-value mono id-cell">${esc(token.id)}</div></div>
          <div class="detail-field"><div class="field-label">Scope</div><div class="field-value">${scopeTags(token.scope)}</div></div>
          <div class="detail-field"><div class="field-label">Issued</div><div class="field-value">${fmtTime(token.issuedAt)}</div></div>
          <div class="detail-field"><div class="field-label">Expires</div><div class="field-value">${fmtTime(token.expiresAt)}</div></div>
          <div class="detail-field"><div class="field-label">Parent</div><div class="field-value">${parent ? `<a href="#tokens/${parent.id}">${esc(parent.subject)}</a>` : "— root token —"}</div></div>
          <div class="detail-field"><div class="field-label">Delegated children</div><div class="field-value">${children.length === 0 ? "none" : children.map((c) => `<a href="#tokens/${c.id}">${esc(c.subject)}</a>`).join(", ")}</div></div>
        </div>
        <div class="toast" id="revoke-toast"></div>
      </div>
    </div>
  `;
  if (canRevoke) {
    document.getElementById("revoke-btn").addEventListener("click", async () => {
      const toast = document.getElementById("revoke-toast");
      try {
        await postJson(`/tokens/${token.id}/revoke`, { reasonCode: "compromised" });
      } catch (err) {
        toast.textContent = err.message;
        toast.className = "toast error";
        return;
      }
      await tick(true);
    });
  }
}

// ---------- Policies ----------

function renderPolicies(main) {
  main.innerHTML = `
    <div class="topbar" style="margin-bottom:16px;"><div></div><button class="btn btn-primary" id="new-policy-btn">+ New policy</button></div>
    <div id="policy-form-slot"></div>
    <div id="policy-list"></div>
  `;
  document.getElementById("new-policy-btn").addEventListener("click", () => showPolicyForm(null));
  renderPolicyList();
}

function renderPolicyList() {
  const el = document.getElementById("policy-list");
  if (STATE.policies.length === 0) {
    el.innerHTML = `<div class="panel"><div class="empty-state"><div class="empty-title">No policies defined</div>Without one attached, requests are checked only against the Enforcement Gateway's baseline rules.</div></div>`;
    return;
  }
  el.innerHTML = STATE.policies.map((p) => `
    <div class="panel">
      <div class="panel-header">
        <h3>${esc(p.name)}</h3>
        <button class="btn btn-secondary btn-sm" data-edit="${p.id}">Edit</button>
      </div>
      <div class="panel-body padded">
        <div class="detail-grid">
          <div class="detail-field"><div class="field-label">Allowed scope</div><div class="field-value">${scopeTags(p.allowedScope)}</div></div>
          <div class="detail-field"><div class="field-label">Max TTL</div><div class="field-value">${p.maxTtlSeconds}s</div></div>
          <div class="detail-field"><div class="field-label">Authored by</div><div class="field-value">${esc(p.authoredBy)}</div></div>
          <div class="detail-field"><div class="field-label">Last updated</div><div class="field-value">${fmtTime(p.updatedAt)}</div></div>
        </div>
      </div>
      <div id="edit-slot-${p.id}"></div>
    </div>
  `).join("");
  el.querySelectorAll("button[data-edit]").forEach((btn) => {
    btn.addEventListener("click", () => showPolicyForm(btn.dataset.edit));
  });
}

function showPolicyForm(policyId) {
  formOpen = true;
  const policy = policyId ? STATE.policies.find((p) => p.id === policyId) : null;
  const slot = policyId ? document.getElementById(`edit-slot-${policyId}`) : document.getElementById("policy-form-slot");
  slot.innerHTML = `
    <div class="panel" style="margin-top:${policyId ? "0" : "0"};">
      <div class="panel-header"><h3>${policy ? "Edit policy" : "New policy"}</h3></div>
      <div class="panel-body padded">
        <div class="field"><label>Name</label><input id="pf-name" value="${policy ? esc(policy.name) : ""}" placeholder="Standard agent access" /></div>
        <div class="field"><label>Allowed scope (comma-separated)</label><input id="pf-scope" value="${policy ? esc(policy.allowedScope.join(", ")) : ""}" placeholder="email:send, crm:read" /></div>
        <div class="field"><label>Max TTL (seconds)</label><input id="pf-ttl" value="${policy ? policy.maxTtlSeconds : ""}" placeholder="3600" /></div>
        <div class="field"><label>Authored by</label><input id="pf-author" value="policy-manager-1" /></div>
        <button class="btn btn-primary" id="pf-save">${policy ? "Save changes" : "Create policy"}</button>
        <button class="btn btn-secondary" id="pf-cancel">Cancel</button>
        <div class="toast" id="pf-toast"></div>
      </div>
    </div>
  `;
  document.getElementById("pf-cancel").addEventListener("click", () => { slot.innerHTML = ""; formOpen = false; });
  document.getElementById("pf-save").addEventListener("click", () => savePolicy(policyId, slot));
}

async function savePolicy(policyId, slot) {
  const name = document.getElementById("pf-name").value.trim();
  const allowedScope = document.getElementById("pf-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const maxTtlSeconds = Number(document.getElementById("pf-ttl").value);
  const authoredBy = document.getElementById("pf-author").value.trim();
  const toast = document.getElementById("pf-toast");
  try {
    if (policyId) {
      await patchJson(`/policies/${policyId}`, { name, allowedScope, maxTtlSeconds, authoredBy });
    } else {
      await postJson("/policies", { name, allowedScope, maxTtlSeconds, authoredBy });
    }
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  slot.innerHTML = "";
  formOpen = false;
  await tick(true);
}

// ---------- Audit Log ----------

function renderAudit(main) {
  main.innerHTML = `
    <div class="field" style="max-width:320px; margin-bottom:14px;">
      <input id="audit-filter" placeholder="Filter by subject, action, or reason…" />
    </div>
    <div class="panel"><div class="panel-body" id="audit-body"></div></div>
  `;
  document.getElementById("audit-filter").addEventListener("input", (e) => renderAuditRows(e.target.value));
  renderAuditRows("");
}

function renderAuditRows(filter) {
  const body = document.getElementById("audit-body");
  const q = filter.trim().toLowerCase();
  const rows = [...STATE.auditLog].reverse().filter((e) =>
    !q || [e.subject, e.action, e.decision, e.reasonCode, e.actor].some((v) => v && String(v).toLowerCase().includes(q))
  );
  if (rows.length === 0) {
    body.innerHTML = `<div class="empty-state"><div class="empty-title">${STATE.auditLog.length === 0 ? "Nothing logged yet" : "No entries match"}</div></div>`;
    return;
  }
  body.innerHTML = `<table class="data-table"><thead><tr><th>When</th><th>Subject / Actor</th><th>Action</th><th>Decision</th><th>Detail</th></tr></thead>
    <tbody>${rows.map((e) => `
      <tr>
        <td class="mono id-cell">${fmtTime(e.occurredAt)}</td>
        <td>${esc(e.subject)}${e.actor ? ` <span style="color:var(--muted-weak);">via ${esc(e.actor)}</span>` : ""}</td>
        <td class="mono">${esc(e.action)}</td>
        <td>${decisionBadge(e)}${e.outcome ? ` <span class="badge badge-neutral">${esc(e.outcome)}</span>` : ""}</td>
        <td style="color:var(--muted-weak);">${esc(e.reasonCode || "—")}</td>
      </tr>
    `).join("")}</tbody></table>`;
}

// ---------- chrome / router ----------

function renderNav(activeTabId) {
  const nav = document.getElementById("nav");
  const pendingCount = STATE.requests.length;
  nav.innerHTML = TABS.map((t) => {
    const badge = t.badgeKey === "pendingCount" && pendingCount > 0 ? `<span class="nav-badge">${pendingCount}</span>` : "";
    return `<button class="nav-item${t.id === activeTabId ? " active" : ""}" data-tab="${t.id}">${t.icon()}<span>${t.label}</span>${badge}</button>`;
  }).join("");
  nav.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => { location.hash = `#${btn.dataset.tab}`; });
  });
}

function renderDataAsOf() {
  const el = document.getElementById("data-as-of");
  if (!STATE.lastFetchedAt) { el.textContent = ""; return; }
  el.innerHTML = `<span class="live-dot"></span>Live · updated ${relTime(STATE.lastFetchedAt.toISOString())}`;
}

function currentTabId() {
  const id = (location.hash || "#overview").slice(1).split("/")[0];
  return TABS.some((t) => t.id === id) ? id : "overview";
}

const TAB_COPY = {
  overview: ["Overview", "What's happening across Ambit right now."],
  requests: ["Requests", "Every token request waits here until a human approves or denies it."],
  tokens: ["Tokens", "Every token this process has issued — active, revoked, and their delegation lineage."],
  policies: ["Policies", "Human-authored constraints on what a token can be issued with. Modifying one takes effect on the next issuance checked against it."],
  audit: ["Audit Log", "Every allowed, denied, and administrative action — immutable, timestamped."],
};

let lastRenderedTabId = null;

async function render() {
  const tabId = currentTabId();
  renderNav(tabId);
  renderDataAsOf();
  const [title, desc] = TAB_COPY[tabId];
  document.getElementById("page-title").textContent = title;
  document.getElementById("page-desc").textContent = desc;
  const main = document.getElementById("tab-content");
  // Fade in only when the tab actually changes — background poll refreshes
  // (every 4s) shouldn't flicker the content the user is looking at.
  if (tabId !== lastRenderedTabId) {
    main.classList.remove("fade-in");
    void main.offsetWidth;
    main.classList.add("fade-in");
    lastRenderedTabId = tabId;
  }

  const renderers = {
    overview: renderOverview,
    requests: renderRequests,
    tokens: renderTokens,
    policies: renderPolicies,
    audit: renderAudit,
  };
  renderers[tabId](main);
}

// A background poll tick fully re-renders the current tab from scratch. If
// that fires while an operator is mid-typing in any form (new/edit policy,
// submit request), it would silently wipe out their input from under them
// — a live-refreshing console must never do that. So: still refresh the
// underlying data (nothing goes stale for when they're done), but skip the
// destructive re-render while any field inside the tab content has focus.
function formFieldIsFocused() {
  const active = document.activeElement;
  const tabContent = document.getElementById("tab-content");
  return !!(active && tabContent && tabContent.contains(active) && ["INPUT", "SELECT", "TEXTAREA"].includes(active.tagName));
}

async function tick(force = false) {
  let changed = false;
  try {
    changed = await refreshAll();
  } catch (err) {
    console.error("refresh failed", err);
  }
  if (force || (changed && !(formOpen || formFieldIsFocused()))) {
    render();
  } else {
    renderDataAsOf(); // still reflect the successful sync time, even with no visible change
  }
}

window.addEventListener("hashchange", () => {
  formOpen = false; // leaving the tab — any open form here no longer exists
  render();
});
tick(true);
setInterval(() => tick(false), POLL_MS);
