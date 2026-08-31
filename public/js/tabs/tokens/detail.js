import { STATE, postJson } from "../../state.js";
import { esc, fmtTime, tokenStatusBadge, scopeTags } from "../../format.js";
import { confirmAction } from "../../confirm.js";
import { renderDelegatePanel } from "./delegate.js";
import { renderCustomerDataPanel } from "./customerData.js";

export function renderTokenDetail(main, id, tick) {
  const token = STATE.tokens.find((t) => t.id === id);
  if (!token) {
    main.innerHTML = `<a class="back-link" href="#tokens">← Tokens</a><div class="empty-state">No token "${esc(id)}" found.</div>`;
    return;
  }
  const parent = token.parentTokenId ? STATE.tokens.find((t) => t.id === token.parentTokenId) : null;
  const children = STATE.tokens.filter((t) => t.parentTokenId === token.id);
  const canRevoke = token.status === "active";

  main.innerHTML = `
    <div class="panel">
      <div class="panel-header detail-header">
        <h3>${esc(token.subject)} ${tokenStatusBadge(token)}</h3>
        ${canRevoke ? `<button class="btn btn-danger btn-sm" id="revoke-btn">Revoke</button>` : ""}
      </div>
      <div class="panel-body padded">
        <div class="detail-grid mb-3">
          <div class="detail-field"><div class="field-label">Token ID</div><div class="field-value mono id-cell">${esc(token.id)}</div></div>
          <div class="detail-field"><div class="field-label">Scope</div><div class="field-value">${scopeTags(token.scope)}</div></div>
          <div class="detail-field"><div class="field-label">Issued</div><div class="field-value">${fmtTime(token.issuedAt)}</div></div>
          <div class="detail-field"><div class="field-label">Expires</div><div class="field-value">${fmtTime(token.expiresAt)}</div></div>
          ${token.status === "revoked" ? `
          <div class="detail-field"><div class="field-label">Revoked</div><div class="field-value">${fmtTime(token.revokedAt)}</div></div>
          <div class="detail-field"><div class="field-label">Revocation reason</div><div class="field-value">${esc(token.revocationReason || "—")}</div></div>` : ""}
        </div>

        <div class="detail-field mb-3">
          <div class="field-label">Delegation lineage</div>
          <div class="lineage-chain">
            ${parent ? `<a class="lineage-node" href="#tokens/${parent.id}">${esc(parent.subject)}</a><span class="lineage-arrow">→</span>` : ""}
            <span class="lineage-node current">${esc(token.subject)}</span>
            ${children.length ? `<span class="lineage-arrow">→</span><span class="lineage-children">${children.map((c) => `<a class="lineage-node" href="#tokens/${c.id}">${esc(c.subject)}</a>`).join("")}</span>` : ""}
          </div>
          ${!parent && children.length === 0 ? `<p class="text-tertiary text-sm mt-2 mb-0">Root token — no parent, no delegated children.</p>` : ""}
        </div>

        <div class="toast" id="revoke-toast"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h3>Actions</h3></div>
      <div class="panel-body padded">
        <div id="delegate-panel-slot"></div>
        <hr class="section-divider" />
        <div id="customer-data-panel-slot"></div>
      </div>
    </div>
  `;

  renderDelegatePanel(document.getElementById("delegate-panel-slot"), token, tick);
  renderCustomerDataPanel(document.getElementById("customer-data-panel-slot"), token, tick);

  if (canRevoke) {
    document.getElementById("revoke-btn").addEventListener("click", async () => {
      const ok = await confirmAction({
        title: "Revoke this token?",
        body: "This immediately blocks the token and cascades to every delegated child. This cannot be undone.",
        confirmLabel: "Revoke token",
      });
      if (!ok) return;
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
