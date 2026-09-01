import { STATE, postJson, patchJson, setFormOpen } from "../state.js";
import { esc, fmtTime, scopeTags } from "../format.js";
import { currentUsername } from "../auth.js";
import { updateAuthWidget } from "../chrome.js";

// ADR-015 (Control hardening): creating and editing a policy now requires a
// real operator session — authoredBy is derived from it server-side, no
// longer a free-text field the console fills in for you.
export function renderPolicies(main, tick) {
  main.innerHTML = `
    ${!currentUsername() ? `<div class="stale-warning">Not signed in — creating or editing a policy needs a real operator login (top right).</div>` : ""}
    <div class="flex-between mb-3"><div></div><button class="btn btn-primary" id="new-policy-btn">+ New policy</button></div>
    <div id="policy-form-slot"></div>
    <div id="policy-list"></div>
  `;
  document.getElementById("new-policy-btn").addEventListener("click", () => showPolicyForm(null, tick));
  renderPolicyList(tick);
}

function renderPolicyList(tick) {
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
    btn.addEventListener("click", () => showPolicyForm(btn.dataset.edit, tick));
  });
}

function showPolicyForm(policyId, tick) {
  setFormOpen(true);
  const policy = policyId ? STATE.policies.find((p) => p.id === policyId) : null;
  const slot = policyId ? document.getElementById(`edit-slot-${policyId}`) : document.getElementById("policy-form-slot");
  slot.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h3>${policy ? "Edit policy" : "New policy"}</h3></div>
      <div class="panel-body padded">
        <div class="field"><label>Name</label><input id="pf-name" value="${policy ? esc(policy.name) : ""}" placeholder="Standard agent access" /></div>
        <div class="field"><label>Allowed scope (comma-separated)</label><input id="pf-scope" value="${policy ? esc(policy.allowedScope.join(", ")) : ""}" placeholder="email:send, crm:read" /></div>
        <div class="field"><label>Max TTL (seconds)</label><input id="pf-ttl" value="${policy ? policy.maxTtlSeconds : ""}" placeholder="3600" /></div>
        <p class="text-tertiary text-xs mt-0 mb-2">Authored by will be recorded as <strong>${esc(currentUsername() || "— log in first —")}</strong>, your real signed-in identity.</p>
        <button class="btn btn-primary" id="pf-save">${policy ? "Save changes" : "Create policy"}</button>
        <button class="btn btn-secondary" id="pf-cancel">Cancel</button>
        <div class="toast" id="pf-toast"></div>
      </div>
    </div>
  `;
  document.getElementById("pf-cancel").addEventListener("click", () => { slot.innerHTML = ""; setFormOpen(false); });
  document.getElementById("pf-save").addEventListener("click", () => savePolicy(policyId, slot, tick));
}

async function savePolicy(policyId, slot, tick) {
  const name = document.getElementById("pf-name").value.trim();
  const allowedScope = document.getElementById("pf-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const maxTtlSeconds = Number(document.getElementById("pf-ttl").value);
  const toast = document.getElementById("pf-toast");
  if (!currentUsername()) {
    toast.textContent = "Log in first — top right.";
    toast.className = "toast error";
    return;
  }
  try {
    if (policyId) {
      await patchJson(`/policies/${policyId}`, { name, allowedScope, maxTtlSeconds });
    } else {
      await postJson("/policies", { name, allowedScope, maxTtlSeconds });
    }
  } catch (err) {
    updateAuthWidget(); // in case a 401 cleared an expired session
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  slot.innerHTML = "";
  setFormOpen(false);
  await tick(true);
}
