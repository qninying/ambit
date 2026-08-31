// Mirrors policies.js's list+create shape — deliberately no edit/PATCH,
// matching the real API (POST/GET /redaction-rules only; a new rule is how
// a mistaken one gets superseded, per src/server.ts's own comment).

import { STATE, postJson, setFormOpen } from "../state.js";
import { esc, fmtTime } from "../format.js";
import { actingAs } from "../session.js";

export function renderRedactionRules(main, tick) {
  main.innerHTML = `
    <div class="flex-between mb-3"><div></div><button class="btn btn-primary" id="new-rule-btn">+ New rule</button></div>
    <div id="rule-form-slot"></div>
    <div id="rule-list"></div>
  `;
  document.getElementById("new-rule-btn").addEventListener("click", () => showRuleForm(tick));
  renderRuleList();
}

function renderRuleList() {
  const el = document.getElementById("rule-list");
  if (STATE.redactionRules.length === 0) {
    el.innerHTML = `<div class="panel"><div class="empty-state"><div class="empty-title">No redaction rules defined</div>Customer-data access has nothing to check field visibility against.</div></div>`;
    return;
  }
  el.innerHTML = STATE.redactionRules.map((r) => {
    const fields = Object.entries(r.sensitiveFields || {});
    return `
      <div class="panel">
        <div class="panel-header"><h3>${esc(r.name)}</h3></div>
        <div class="panel-body">
          <div class="table-scroll">
            <table class="data-table">
              <thead><tr><th>Sensitive field</th><th>Required scope to view unredacted</th></tr></thead>
              <tbody>${fields.map(([field, scope]) => `<tr><td class="mono">${esc(field)}</td><td class="tag">${esc(scope)}</td></tr>`).join("")}</tbody>
            </table>
          </div>
          <div class="detail-grid mt-3" style="padding:0 var(--space-5) var(--space-4);">
            <div class="detail-field"><div class="field-label">Authored by</div><div class="field-value">${esc(r.authoredBy)}</div></div>
            <div class="detail-field"><div class="field-label">Created</div><div class="field-value">${fmtTime(r.createdAt)}</div></div>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function showRuleForm(tick) {
  setFormOpen(true);
  const slot = document.getElementById("rule-form-slot");
  slot.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h3>New redaction rule</h3></div>
      <div class="panel-body padded">
        <div class="field"><label>Name</label><input id="rf-name" placeholder="Standard Customer PII" /></div>
        <div class="field">
          <label>Sensitive fields (one per line: <code>field:requiredScope</code>)</label>
          <textarea id="rf-fields" rows="4" placeholder="ssn:customer:read:ssn&#10;email:customer:read:email" style="width:100%; padding:8px 10px; border:1px solid var(--border); border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:12.5px; background:var(--surface); color:var(--text);"></textarea>
          <div class="hint">Each line maps one field name to the scope required to see it unredacted.</div>
        </div>
        <div class="field"><label>Authored by</label><input id="rf-author" value="${esc(actingAs())}" /></div>
        <button class="btn btn-primary" id="rf-save">Create rule</button>
        <button class="btn btn-secondary" id="rf-cancel">Cancel</button>
        <div class="toast" id="rf-toast"></div>
      </div>
    </div>
  `;
  document.getElementById("rf-cancel").addEventListener("click", () => { slot.innerHTML = ""; setFormOpen(false); });
  document.getElementById("rf-save").addEventListener("click", () => saveRule(slot, tick));
}

async function saveRule(slot, tick) {
  const name = document.getElementById("rf-name").value.trim();
  const authoredBy = document.getElementById("rf-author").value.trim();
  const toast = document.getElementById("rf-toast");
  const lines = document.getElementById("rf-fields").value.split("\n").map((l) => l.trim()).filter(Boolean);
  const sensitiveFields = {};
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const field = line.slice(0, idx).trim();
    const scope = line.slice(idx + 1).trim();
    if (field && scope) sensitiveFields[field] = scope;
  }
  try {
    await postJson("/redaction-rules", { name, sensitiveFields, authoredBy });
  } catch (err) {
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  slot.innerHTML = "";
  setFormOpen(false);
  await tick(true);
}
