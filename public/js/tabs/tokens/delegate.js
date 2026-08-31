// Delegate panel — REQ-003/REQ-012: a subagent's token, narrowed from a
// parent's. Mounted inline on the token detail view (not a separate route)
// so it reuses the existing formOpen guard and hash router exactly as the
// policy edit-form does.

import { postJson, setFormOpen } from "../../state.js";
import { esc, scopeTags } from "../../format.js";

const DENIAL_COPY = {
  parent_invalid: "The parent token no longer exists or isn't active.",
  empty_scope: "A delegated token needs at least one scope.",
  exceeds_parent_scope: "The requested scope isn't a subset of the parent's — delegation can only narrow, never broaden.",
  not_narrower: "The requested scope equals the parent's — a delegated token must be strictly narrower.",
  store_unavailable: "The Token Store is currently failing closed (circuit breaker open).",
};

export function renderDelegatePanel(slot, token, tick) {
  slot.innerHTML = `
    <button class="btn btn-secondary btn-sm" id="delegate-open-btn">Delegate a narrower token</button>
    <div id="delegate-form-slot"></div>
  `;
  document.getElementById("delegate-open-btn").addEventListener("click", () => showForm(slot, token, tick));
}

function showForm(slot, token, tick) {
  setFormOpen(true);
  const formSlot = document.getElementById("delegate-form-slot");
  formSlot.innerHTML = `
    <div class="panel mt-3">
      <div class="panel-header"><h3>Delegate from ${esc(token.subject)}</h3></div>
      <div class="panel-body padded">
        <p class="text-secondary text-sm mt-0">The child's scope must be a strict subset of the parent's (${scopeTags(token.scope)}) and cannot outlive it.</p>
        <div class="form-row">
          <div class="field"><label>Subagent subject</label><input id="dg-subject" placeholder="${esc(token.subject)}-worker" /></div>
          <div class="field"><label>Scope (comma-separated)</label><input id="dg-scope" placeholder="${esc(token.scope[0] || "email:send")}" /></div>
        </div>
        <div class="field" style="max-width:200px;"><label>TTL (seconds)</label><input id="dg-ttl" placeholder="120" /></div>
        <button class="btn btn-primary" id="dg-submit">Request delegation</button>
        <button class="btn btn-secondary" id="dg-cancel">Cancel</button>
        <div id="dg-result"></div>
      </div>
    </div>
  `;
  document.getElementById("dg-cancel").addEventListener("click", () => { formSlot.innerHTML = ""; setFormOpen(false); });
  document.getElementById("dg-submit").addEventListener("click", () => submit(token, formSlot, tick));
}

async function submit(token, formSlot, tick) {
  const subject = document.getElementById("dg-subject").value.trim();
  const scope = document.getElementById("dg-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttlSeconds = Number(document.getElementById("dg-ttl").value);
  const result = document.getElementById("dg-result");
  let decision;
  try {
    decision = await postJson(`/tokens/${token.id}/delegate`, { subject, scope, ttlSeconds });
  } catch (err) {
    result.innerHTML = `<div class="toast error">${esc(err.message)}</div>`;
    return;
  }
  if (decision.approved) {
    result.innerHTML = `<div class="toast ok">Delegated — <a href="#tokens/${decision.token.id}">${esc(decision.token.subject)}</a> issued with ${scopeTags(decision.token.scope)}.</div>`;
    setFormOpen(false);
    await tick(true);
  } else {
    result.innerHTML = `<div class="toast error">Denied (${esc(decision.reasonCode)}) — ${esc(DENIAL_COPY[decision.reasonCode] || "")}</div>`;
  }
}
