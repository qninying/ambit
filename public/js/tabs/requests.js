import { STATE, postJson } from "../state.js";
import { esc, fmtTime, scopeTags } from "../format.js";
import { currentUsername } from "../auth.js";
import { updateAuthWidget } from "../chrome.js";
import { confirmAction } from "../confirm.js";

export function renderRequests(main, tick) {
  const list = STATE.requests;
  main.innerHTML = `
    ${list.length > 0 && !currentUsername() ? `<div class="stale-warning">Not signed in — approving or denying a request needs a real operator login (top right). Submitting a test request doesn't.</div>` : ""}
    <div class="panel">
      <div class="panel-header"><h3>Pending requests</h3><span class="panel-meta">${list.length} waiting</span></div>
      <div class="panel-body padded" id="requests-list"></div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Submit a test request</h3></div>
      <div class="panel-body padded">
        <p class="page-desc mt-0" style="margin-bottom:12px;">Stands in for the client SDK — a real agent would submit this programmatically via <code>sdk/ambitClient.ts</code>. Requires a real, registered agent credential — subject is derived from it, never typed in (see ADR-012).</p>
        <div class="form-row">
          <div class="field" style="flex:2;"><label>Agent credential</label><input id="req-credential" placeholder="paste a registered agent's credential, or register one below" /></div>
          <div class="field"><label>Scope (comma-separated)</label><input id="req-scope" placeholder="email:send, crm:read" /></div>
        </div>
        <div class="form-row">
          <div class="field" style="max-width:200px;"><label>TTL (seconds)</label><input id="req-ttl" placeholder="300" /></div>
        </div>
        <hr class="section-divider" />
        <div class="field">
          <label>Register a new test agent (needs your own operator login)</label>
          <div class="form-row">
            <div class="field"><input id="new-agent-subject" placeholder="e.g. billing-agent" /></div>
            <button class="btn btn-secondary btn-sm" id="register-agent-btn" style="align-self:flex-start;">Register + fill credential</button>
          </div>
          <div class="toast" id="register-agent-toast"></div>
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
    // Policy is the approver's own choice, made here at approval time —
    // never something the requester pre-selected. See ADR-010: a
    // requester-chosen policy would make "policy attached" a self-issued
    // rubber stamp with no real governance value.
    const policyOptions = `<option value="">— no policy —</option>${STATE.policies.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}`;
    listEl.innerHTML = list.map((r) => `
      <div class="panel flush" style="margin:0 0 12px; border:1px solid var(--border);" data-id="${r.id}">
        <div class="panel-body padded">
          <div style="font-weight:700; font-size:var(--text-md); margin-bottom:2px;">${esc(r.subject)}</div>
          <div style="font-size:var(--text-base); color:var(--text); margin-bottom:8px;">Requesting ${scopeTags(r.scope)} — valid ${r.ttlSeconds}s if approved</div>
          <div class="text-tertiary text-xs" style="margin-bottom:10px;">Requested ${fmtTime(r.requestedAt)}</div>
          <div class="field" style="max-width:280px;">
            <label>Policy to apply on approval (your choice, not theirs)</label>
            <select class="approve-policy-select" data-request-id="${r.id}">${policyOptions}</select>
          </div>
          <button class="btn btn-ok btn-sm" data-action="approve" data-id="${r.id}">Approve</button>
          <button class="btn btn-danger btn-sm" data-action="deny" data-id="${r.id}">Deny</button>
          <div class="toast" data-toast-for="${r.id}"></div>
        </div>
      </div>
    `).join("");
    listEl.querySelectorAll("button[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => decideRequest(btn.dataset.id, btn.dataset.action, tick));
    });
  }

  document.getElementById("req-submit").addEventListener("click", () => submitTestRequest(tick));
  document.getElementById("register-agent-btn").addEventListener("click", registerTestAgent);
}

// ADR-012: registers a real agent identity via the real POST /agent-identities
// route, using the operator's own session — then fills the credential field
// so the demo stays functional without secretly bypassing the mechanism it's
// supposed to be exercising.
async function registerTestAgent() {
  const toast = document.getElementById("register-agent-toast");
  const subject = document.getElementById("new-agent-subject").value.trim();
  if (!currentUsername()) {
    toast.textContent = "Log in first — top right.";
    toast.className = "toast error";
    return;
  }
  if (!subject) {
    toast.textContent = "Give the new agent a subject name first.";
    toast.className = "toast error";
    return;
  }
  try {
    const { credential } = await postJson("/agent-identities", { subject });
    const credentialField = document.getElementById("req-credential");
    credentialField.value = credential;
    // Registering logs an audit-log entry, which can make the next poll
    // tick see changed data — and with nothing focused, formFieldIsFocused()
    // wouldn't protect this freshly-filled field from being wiped by the
    // resulting re-render. Focus it so it's protected like any field the
    // operator typed into directly.
    credentialField.focus();
    toast.textContent = `Registered "${subject}" — credential filled in above.`;
    toast.className = "toast ok";
  } catch (err) {
    updateAuthWidget(); // in case postJson cleared an expired session on a 401
    toast.textContent = err.message;
    toast.className = "toast error";
  }
}

async function decideRequest(id, action, tick) {
  const card = document.querySelector(`[data-id="${id}"]`);
  const toast = card.querySelector(`[data-toast-for="${id}"]`);
  // ADR-011: approve/deny require a real session now — approver is derived
  // from it server-side, never sent by the client. Checked client-side
  // first purely as a UX nicety (skip an obviously-doomed round-trip); the
  // server's own requireSession check is what actually enforces this.
  if (!currentUsername()) {
    toast.textContent = "Log in first — top right.";
    toast.className = "toast error";
    return;
  }
  if (action === "deny") {
    const ok = await confirmAction({
      title: "Deny this request?",
      body: "The requesting agent will not receive a token. This decision is recorded in the audit log.",
      confirmLabel: "Deny request",
    });
    if (!ok) return;
  }
  card.querySelectorAll("button, select").forEach((el) => (el.disabled = true));
  try {
    const body = {};
    if (action === "approve") {
      const select = card.querySelector(".approve-policy-select");
      if (select && select.value) body.policyId = select.value;
    }
    // REQ-010: reasonCode is a required, closed set on the server
    // (POST /requests/:id/deny 400s on anything else) — "other" here is
    // honest, not a placeholder: this one-click demo button genuinely has
    // no more specific reason to report than "the approver declined it."
    if (action === "deny") body.reasonCode = "other";
    await postJson(`/requests/${id}/${action}`, body);
  } catch (err) {
    updateAuthWidget(); // in case postJson cleared an expired session on a 401
    toast.textContent = err.message;
    toast.className = "toast error";
    card.querySelectorAll("button, select").forEach((el) => (el.disabled = false));
    return;
  }
  await tick(true);
}

async function submitTestRequest(tick) {
  const credential = document.getElementById("req-credential").value.trim();
  const scope = document.getElementById("req-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttlSeconds = Number(document.getElementById("req-ttl").value);
  const toast = document.getElementById("req-toast");
  if (!credential) {
    toast.textContent = "Paste an agent credential first — register one below if you don't have one.";
    toast.className = "toast error";
    return;
  }
  try {
    // Authenticates as the agent (ADR-012), not the console's own operator
    // session — subject is derived server-side from the credential, never
    // sent by this form. Authorization can only carry one value, so this
    // overrides state.js's default of attaching the operator's session
    // token to every POST.
    await postJson("/requests", { scope, ttlSeconds }, { Authorization: `Bearer ${credential}` });
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  toast.textContent = "Request submitted.";
  toast.className = "toast ok";
  await tick(true);
}
