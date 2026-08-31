import { STATE, fetchJson } from "../state.js";
import { esc, fmtTime, decisionBadge } from "../format.js";

let expandedId = null;

export function renderAudit(main) {
  main.innerHTML = `
    <div class="flex-between mb-3">
      <div class="field" style="max-width:320px; margin-bottom:0;">
        <input id="audit-filter" placeholder="Filter by subject, action, or reason…" />
      </div>
      <div id="chain-status" class="text-sm">Checking chain integrity…</div>
    </div>
    <div class="panel"><div class="panel-body" id="audit-body"></div></div>
  `;
  document.getElementById("audit-filter").addEventListener("input", (e) => renderAuditRows(e.target.value));
  renderAuditRows("");
  renderChainStatus();
}

// Fetched on demand, not part of the polled STATE — walking the whole hash
// chain on every 4s tick regardless of which tab is open would be wasted
// work. This is the live, demonstrable proof that "immutable" is a real,
// checkable property here, not just a claim in a comment.
async function renderChainStatus() {
  const el = document.getElementById("chain-status");
  try {
    const result = await fetchJson("/audit-log/verify");
    el.innerHTML = result.valid
      ? `<span class="badge badge-ok"><span class="dot"></span>Chain verified — ${result.entriesChecked} ${result.entriesChecked === 1 ? "entry" : "entries"}</span>`
      : `<span class="badge badge-danger"><span class="dot"></span>Chain broken at entry ${esc(result.brokenAtId)}</span>`;
  } catch (err) {
    el.textContent = "";
  }
}

function detailRow(e) {
  const fields = [
    ["Entry ID", e.id],
    ["Token", e.tokenId || "—"],
    ["Request", e.requestId || "—"],
    ["Policy", e.policyId || "—"],
    ["Outcome", e.outcome || "—"],
    ["Redacted fields", e.redactedFields && e.redactedFields.length ? e.redactedFields.join(", ") : "—"],
    ["Message", e.message || "—"],
    ["Hash", e.hash],
    ["Previous hash", e.previousHash || "— (chain start)"],
  ];
  return `<tr class="expanded-row"><td colspan="5">
    <div class="detail-grid">
      ${fields.map(([label, value]) => `<div class="detail-field"><div class="field-label">${esc(label)}</div><div class="field-value mono" style="word-break:break-all; font-size:11.5px;">${esc(value)}</div></div>`).join("")}
    </div>
  </td></tr>`;
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
  body.innerHTML = `<div class="table-scroll"><table class="data-table"><thead><tr><th>When</th><th>Subject / Actor</th><th>Action</th><th>Decision</th><th>Detail</th></tr></thead>
    <tbody>${rows.map((e) => `
      <tr class="clickable" data-entry="${esc(e.id)}">
        <td class="mono id-cell">${fmtTime(e.occurredAt)}</td>
        <td>${esc(e.subject)}${e.actor ? ` <span class="text-tertiary">via ${esc(e.actor)}</span>` : ""}</td>
        <td class="mono">${esc(e.action)}</td>
        <td>${decisionBadge(e)}${e.outcome ? ` <span class="badge badge-neutral">${esc(e.outcome)}</span>` : ""}</td>
        <td class="text-tertiary">${esc(e.reasonCode || "—")}</td>
      </tr>${e.id === expandedId ? detailRow(e) : ""}
    `).join("")}</tbody></table></div>`;
  body.querySelectorAll("tr[data-entry]").forEach((row) => {
    row.addEventListener("click", () => {
      const id = row.dataset.entry;
      expandedId = expandedId === id ? null : id;
      renderAuditRows(document.getElementById("audit-filter").value);
    });
  });
}
