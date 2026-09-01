import { STATE, postJson, setFormOpen } from "../../state.js";
import { esc, fmtTime, tokenStatusBadge, scopeTags } from "../../format.js";
import { confirmAction } from "../../confirm.js";
import { currentUsername } from "../../auth.js";
import { updateAuthWidget } from "../../chrome.js";
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
        <div class="field mb-3">
          <label>This token's secret</label>
          <input id="held-secret" placeholder="paste the secret you claimed for this token (see ADR-013)" />
          <div class="hint">Delegating and accessing customer data both require proof you actually hold this token — its id alone (shown above) isn't enough. Claim a secret from the Requests tab after approval, or paste one a delegation below just handed you.</div>
        </div>
        <div id="delegate-panel-slot"></div>
        <hr class="section-divider" />
        <div id="customer-data-panel-slot"></div>
      </div>
    </div>
  `;

  // Shared by both subpanels below rather than duplicating the input — a
  // live getter, not a snapshotted value, so it always reads whatever the
  // operator has pasted in at click time (including a child's secret they
  // pasted in after a delegation just below handed it to them).
  const getHeldSecret = () => document.getElementById("held-secret").value.trim();
  renderDelegatePanel(document.getElementById("delegate-panel-slot"), token, tick, getHeldSecret);
  renderCustomerDataPanel(document.getElementById("customer-data-panel-slot"), token, getHeldSecret);

  // A pasted secret loses focus the moment the operator clicks "Delegate" or
  // "Access customer data" to open the next step — formFieldIsFocused()'s
  // usual protection would already be gone by then. isFormOpen() (already
  // holding the whole tab's poll-render off while a subform is open) is
  // reused here for the same purpose: once something real is pasted, treat
  // it exactly like an in-progress form until the operator navigates away
  // (app.js's hashchange handler already resets isFormOpen() there). Only
  // ever turns protection ON here, never off — a subform below may
  // legitimately still be open and relying on the same flag; this field
  // being cleared is not a signal that it's safe to stop protecting that.
  document.getElementById("held-secret").addEventListener("input", (e) => {
    if (e.target.value.trim().length > 0) setFormOpen(true);
  });

  if (canRevoke) {
    document.getElementById("revoke-btn").addEventListener("click", async () => {
      const toast = document.getElementById("revoke-toast");
      // ADR-015: revoking now requires a real operator session (never the
      // token's own secret — see ADR-013's own scoping note on this route).
      // Checked client-side first purely as a UX nicety; the server's own
      // requireSession is what actually enforces it.
      if (!currentUsername()) {
        toast.textContent = "Log in first — top right.";
        toast.className = "toast error";
        return;
      }
      const ok = await confirmAction({
        title: "Revoke this token?",
        body: "This immediately blocks the token and cascades to every delegated child. This cannot be undone.",
        confirmLabel: "Revoke token",
      });
      if (!ok) return;
      try {
        await postJson(`/tokens/${token.id}/revoke`, { reasonCode: "compromised" });
      } catch (err) {
        updateAuthWidget(); // in case a 401 cleared an expired session
        toast.textContent = err.message;
        toast.className = "toast error";
        return;
      }
      await tick(true);
    });
  }
}
