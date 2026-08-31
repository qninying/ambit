// System health: the Policy & Token Store's circuit-breaker state
// (GET /circuit-breaker, already polled into STATE by refreshAll), plus an
// admin-key-gated fault-injection control (POST /circuit-breaker/simulate-
// outage). The two are visually and interactively separated — the toggle
// disables the ENTIRE real store, a materially different blast radius from
// a normal operational action, per src/server.ts's own comment on the route.

import { STATE, postJson } from "../state.js";
import { esc } from "../format.js";
import { confirmAction } from "../confirm.js";

const STATE_COPY = {
  closed: ["Closed — healthy", "Requests are being served normally.", "badge-ok"],
  open: ["Open — failing closed", "The store is unavailable; enforcement, issuance, and delegation are being denied rather than crashing.", "badge-danger"],
  half_open: ["Half-open — probing", "A single trial call is checking whether the store has recovered.", "badge-warn"],
};

export function renderSystem(main, tick) {
  const breakerState = STATE.circuitBreaker?.state || "closed";
  const [label, desc, cls] = STATE_COPY[breakerState] || STATE_COPY.closed;

  main.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h3>Policy &amp; Token Store — circuit breaker</h3></div>
      <div class="panel-body padded">
        <span class="badge ${cls}" style="font-size:13px; padding:6px 14px;"><span class="dot"></span>${esc(label)}</span>
        <p class="text-secondary mt-3 mb-0" style="font-size:var(--text-base);">${esc(desc)}</p>
      </div>
    </div>

    <div class="danger-zone">
      <div class="danger-zone-header">Fault injection (demo)</div>
      <p>Takes down the real Token &amp; Policy Store for every operation system-wide — not a simulated downstream integration. Requires the <code>x-ambit-admin-key</code> header; the key is never stored, only sent with this one request.</p>
      <div class="form-row" style="align-items:flex-end;">
        <div class="field" style="max-width:260px;"><label>Admin key</label><input id="sys-admin-key" type="password" placeholder="ADMIN_TOGGLE_KEY" autocomplete="off" /></div>
        <button class="btn btn-danger" id="sys-outage-on">Simulate outage</button>
        <button class="btn btn-secondary" id="sys-outage-off">Clear outage</button>
      </div>
      <div class="toast" id="sys-toast"></div>
    </div>
  `;

  document.getElementById("sys-outage-on").addEventListener("click", () => toggleOutage(true, tick));
  document.getElementById("sys-outage-off").addEventListener("click", () => toggleOutage(false, tick));
}

async function toggleOutage(down, tick) {
  if (down) {
    const ok = await confirmAction({
      title: "Simulate a real store outage?",
      body: "Every enforce, issue, revoke, delegate, and policy operation will be denied until the breaker recovers or you clear this.",
      confirmLabel: "Simulate outage",
    });
    if (!ok) return;
  }
  const key = document.getElementById("sys-admin-key").value;
  const toast = document.getElementById("sys-toast");
  try {
    await postJson("/circuit-breaker/simulate-outage", { down }, { "x-ambit-admin-key": key });
  } catch (err) {
    // Surfaced as-is: the server already distinguishes "ADMIN_TOGGLE_KEY not
    // configured at all" from "wrong/missing header" with different messages.
    toast.textContent = err.message;
    toast.className = "toast error";
    return;
  }
  toast.textContent = down ? "Outage simulated." : "Outage cleared.";
  toast.className = "toast ok";
}
