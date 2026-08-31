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
  invalid_credential: "The pasted secret doesn't match this token — double-check you copied the right one.",
};

export function renderDelegatePanel(slot, token, tick, getHeldSecret) {
  slot.innerHTML = `
    <button class="btn btn-secondary btn-sm" id="delegate-open-btn">Delegate a narrower token</button>
    <div id="delegate-form-slot"></div>
  `;
  document.getElementById("delegate-open-btn").addEventListener("click", () => showForm(slot, token, tick, getHeldSecret));
}

function showForm(slot, token, tick, getHeldSecret) {
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
  document.getElementById("dg-submit").addEventListener("click", () => submit(token, formSlot, tick, getHeldSecret));
}

async function submit(token, formSlot, tick, getHeldSecret) {
  const subject = document.getElementById("dg-subject").value.trim();
  const scope = document.getElementById("dg-scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  const ttlSeconds = Number(document.getElementById("dg-ttl").value);
  const result = document.getElementById("dg-result");
  const heldSecret = getHeldSecret();
  if (!heldSecret) {
    result.innerHTML = `<div class="toast error">Paste this token's own secret above first — delegating requires proving you actually hold it (ADR-013).</div>`;
    return;
  }
  let decision;
  try {
    // ADR-013: delegating spends some of the parent's authority, so it
    // requires the same proof of possession using the parent directly
    // would — the operator's own session is irrelevant here.
    decision = await postJson(`/tokens/${token.id}/delegate`, { subject, scope, ttlSeconds }, { Authorization: `Bearer ${heldSecret}` });
  } catch (err) {
    result.innerHTML = `<div class="toast error">${esc(err.message)}</div>`;
    return;
  }
  if (decision.approved) {
    // The child's secret is handed back here, once, synchronously — same
    // one-time-handback treatment as every other credential in this build.
    // Shown plainly (not stashed anywhere) so the operator can copy it into
    // the "This token's secret" field above if they navigate to the child
    // and want to delegate or access data from it in turn.
    result.innerHTML = `
      <div class="toast ok">Delegated — <a href="#tokens/${decision.token.id}">${esc(decision.token.subject)}</a> issued with ${scopeTags(decision.token.scope)}.</div>
      <div class="field mt-2">
        <label>Child token's secret — shown once, copy it now</label>
        <input readonly value="${esc(decision.secret)}" onclick="this.select()" />
      </div>
    `;
    setFormOpen(true); // keep protecting the tab — the secret above is still sitting unclaimed
    await tick(true);
  } else {
    result.innerHTML = `<div class="toast error">Denied (${esc(decision.reasonCode)}) — ${esc(DENIAL_COPY[decision.reasonCode] || "")}</div>`;
  }
}
