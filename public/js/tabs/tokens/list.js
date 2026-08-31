import { STATE } from "../../state.js";
import { esc, fmtTime, tokenStatusBadge, scopeTags, initials } from "../../format.js";

let filterText = "";
let sortDesc = true;

export function renderTokenList(main) {
  main.innerHTML = `
    <div class="flex-between mb-3">
      <div class="field" style="max-width:320px; margin-bottom:0;">
        <input id="token-filter" placeholder="Filter by subject or scope…" value="${esc(filterText)}" />
      </div>
      <span class="text-tertiary text-xs">${STATE.tokens.length} total</span>
    </div>
    <div class="panel">
      <div class="panel-body" id="token-table-slot"></div>
    </div>
  `;
  document.getElementById("token-filter").addEventListener("input", (e) => {
    filterText = e.target.value;
    renderTable();
  });
  renderTable();
}

function renderTable() {
  const slot = document.getElementById("token-table-slot");
  const q = filterText.trim().toLowerCase();
  let rows = STATE.tokens.filter((t) =>
    !q || t.subject.toLowerCase().includes(q) || t.scope.some((s) => s.toLowerCase().includes(q))
  );
  rows = [...rows].sort((a, b) => sortDesc ? new Date(b.issuedAt) - new Date(a.issuedAt) : new Date(a.issuedAt) - new Date(b.issuedAt));

  if (STATE.tokens.length === 0) {
    slot.innerHTML = `<div class="empty-state"><div class="empty-title">No tokens issued yet</div>Approve a request to issue the first one.</div>`;
    return;
  }
  if (rows.length === 0) {
    slot.innerHTML = `<div class="empty-state"><div class="empty-title">No tokens match "${esc(filterText)}"</div></div>`;
    return;
  }
  slot.innerHTML = `<div class="table-scroll"><table class="data-table">
    <thead><tr>
      <th>Subject</th><th>Scope</th><th>Status</th>
      <th class="sortable" id="th-issued">Issued <span class="sort-caret">${sortDesc ? "▾" : "▴"}</span></th>
      <th>Expires</th><th>Lineage</th>
    </tr></thead>
    <tbody>${rows.map((t) => `
      <tr class="clickable" data-id="${t.id}">
        <td><div class="identity-cell"><div class="identity-avatar">${esc(initials(t.subject))}</div>${esc(t.subject)}</div></td>
        <td>${scopeTags(t.scope)}</td>
        <td>${tokenStatusBadge(t)}</td>
        <td>${fmtTime(t.issuedAt)}</td>
        <td>${fmtTime(t.expiresAt)}</td>
        <td>${t.parentTokenId ? `<span class="badge badge-accent">delegated</span>` : `<span class="badge badge-neutral">root</span>`}</td>
      </tr>
    `).join("")}</tbody>
  </table></div>`;
  slot.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", () => { location.hash = `#tokens/${row.dataset.id}`; });
  });
  const th = document.getElementById("th-issued");
  if (th) th.addEventListener("click", () => { sortDesc = !sortDesc; renderTable(); });
}
