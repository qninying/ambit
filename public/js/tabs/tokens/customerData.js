// Customer-data access demo panel — REQ-009: the one place field-level
// redaction becomes visible end-to-end (token -> Enforcement Gateway ->
// redaction). Only 2 hardcoded demo customers exist server-side
// (cust-001/cust-002); there's no customer-listing endpoint, so this is
// deliberately a fixed picker, not an open-ended search.

import { postJson, setFormOpen } from "../../state.js";
import { esc } from "../../format.js";

const DEMO_CUSTOMERS = ["cust-001", "cust-002"];

export function renderCustomerDataPanel(slot, token, getHeldSecret) {
  slot.innerHTML = `
    <button class="btn btn-secondary btn-sm" id="cd-open-btn">Access customer data</button>
    <div id="cd-form-slot"></div>
  `;
  document.getElementById("cd-open-btn").addEventListener("click", () => showForm(slot, token, getHeldSecret));
}

function showForm(slot, token, getHeldSecret) {
  setFormOpen(true);
  const formSlot = document.getElementById("cd-form-slot");
  formSlot.innerHTML = `
    <div class="panel mt-3">
      <div class="panel-header"><h3>Access customer data as ${esc(token.subject)}</h3></div>
      <div class="panel-body padded">
        <p class="text-secondary text-sm mt-0">Runs the real Enforcement Gateway, then applies the server's configured default redaction rule. Fields this token's scope doesn't unlock come back masked.</p>
        <div class="field" style="max-width:200px;">
          <label>Demo customer</label>
          <select id="cd-customer">${DEMO_CUSTOMERS.map((c) => `<option value="${c}">${c}</option>`).join("")}</select>
        </div>
        <button class="btn btn-primary" id="cd-submit">Access record</button>
        <button class="btn btn-secondary" id="cd-cancel">Close</button>
        <div id="cd-result" class="mt-3"></div>
      </div>
    </div>
  `;
  document.getElementById("cd-cancel").addEventListener("click", () => { formSlot.innerHTML = ""; setFormOpen(false); });
  document.getElementById("cd-submit").addEventListener("click", () => submit(token, formSlot, getHeldSecret));
}

async function submit(token, formSlot, getHeldSecret) {
  const customerId = document.getElementById("cd-customer").value;
  const result = document.getElementById("cd-result");
  const heldSecret = getHeldSecret();
  if (!heldSecret) {
    result.innerHTML = `<div class="toast error">Paste this token's own secret above first — accessing data through it requires proving you actually hold it (ADR-013).</div>`;
    return;
  }
  let res;
  try {
    // ADR-013: this is where redaction-protected PII actually gets
    // exposed — proof of possession here matters more than anywhere else
    // in this build, not less.
    res = await postJson(`/tokens/${token.id}/customer-data/${customerId}`, {}, { Authorization: `Bearer ${heldSecret}` });
  } catch (err) {
    result.innerHTML = `<div class="toast error">${esc(err.message)}</div>`;
    return;
  }
  if (!res.allowed) {
    result.innerHTML = `<div class="toast error">Denied (${esc(res.reasonCode)})${res.message ? ` — ${esc(res.message)}` : ""}</div>`;
    return;
  }
  const redacted = new Set(res.redactedFields || []);
  const fields = Object.entries(res.data || {}).filter(([k]) => k !== "id");
  result.innerHTML = `
    <div class="detail-grid">
      ${fields.map(([field, value]) => `
        <div class="detail-field">
          <div class="field-label">${esc(field)}</div>
          <div class="field-value">
            <span class="tag ${redacted.has(field) ? "tag-redacted" : "tag-unlocked"}">${esc(String(value))}</span>
          </div>
        </div>
      `).join("")}
    </div>
    <p class="text-tertiary text-xs mt-3 mb-0">${redacted.size === 0 ? "No fields redacted for this token." : `Redacted: ${[...redacted].join(", ")}`}</p>
  `;
}
