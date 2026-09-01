// Shared confirmation dialog for destructive actions (deny, revoke,
// simulate-outage). Zero internal dependencies — a leaf module like
// format.js/theme.js. Returns a Promise<boolean> so call sites read as
// `if (!(await confirmAction({...}))) return;`.

import { esc } from "./format.js";

export function confirmAction({ title, body, confirmLabel = "Confirm", danger = true }) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
      <div class="modal-box" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <h4 id="confirm-title">${esc(title)}</h4>
        <p>${esc(body)}</p>
        <div class="modal-actions">
          <button class="btn btn-secondary btn-sm" id="confirm-cancel">Cancel</button>
          <button class="btn ${danger ? "btn-danger" : "btn-primary"} btn-sm" id="confirm-ok">${esc(confirmLabel)}</button>
        </div>
      </div>
    `;
    function close(result) {
      document.removeEventListener("keydown", onKeydown);
      overlay.remove();
      resolve(result);
    }
    function onKeydown(e) {
      if (e.key === "Escape") close(false);
    }
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(false); });
    document.addEventListener("keydown", onKeydown);
    document.body.appendChild(overlay);
    overlay.querySelector("#confirm-cancel").addEventListener("click", () => close(false));
    overlay.querySelector("#confirm-ok").addEventListener("click", () => close(true));
    overlay.querySelector("#confirm-ok").focus();
  });
}
