import { STATE, postJson } from "../state.js";
import { esc, fmtTime, scopeTags } from "../format.js";
import { actingAs } from "../session.js";
import { confirmAction } from "../confirm.js";

export function renderRequests(main, tick) {
  const list = STATE.requests;
  main.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h3>Pending requests</h3><span class="panel-meta">${list.length} waiting</span></div>
      <div class="panel-body padded" id="requests-list"></div>
    </div>
    <div class="panel">
      <div class="panel-header"><h3>Submit a test request</h3></div>
      <div class="panel-body padded">
        <p class="page-desc mt-0" style="margin-bottom:12px;">Stands in for the client SDK — a real agent would submit this programmatically via <code>sdk/ambitClient.ts</code>.</p>
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
      <div class="panel flush" style="margin:0 0 12px; border:1px solid var(--border);" data-id="${r.id}">
        <div class="panel-body padded">
          <div style="font-weight:700; font-size:var(--text-md); margin-bottom:2px;">${esc(r.subject)}</div>
          <div style="font-size:var(--text-base); color:var(--text); margin-bottom:8px;">Requesting ${scopeTags(r.scope)} — valid ${r.ttlSeconds}s if approved${r.policyId ? ` <span class="badge badge-accent">policy attached</span>` : ""}</div>
          <div class="text-tertiary text-xs" style="margin-bottom:10px;">Requested ${fmtTime(r.requestedAt)}</div>
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
}

async function decideRequest(id, action, tick) {
  if (action === "deny") {
    const ok = await confirmAction({
      title: "Deny this request?",
      body: "The requesting agent will not receive a token. This decision is recorded in the audit log.",
      confirmLabel: "Deny request",
    });
    if (!ok) return;
  }
  const card = document.querySelector(`[data-id="${id}"]`);
  const toast = card.querySelector(`[data-toast-for="${id}"]`);
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    const body = { approver: actingAs() };
    // REQ-010: reasonCode is a required, closed set on the server
    // (POST /requests/:id/deny 400s on anything else) — "other" here is
    // honest, not a placeholder: this one-click demo button genuinely has
    // no more specific reason to report than "the approver declined it."
    if (action === "deny") body.reasonCode = "other";
    await postJson(`/requests/${id}/${action}`, body);
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    card.querySelectorAll("button").forEach((b) => (b.disabled = false));
    return;
  }
  await tick(true);
}

async function submitTestRequest(tick) {
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
