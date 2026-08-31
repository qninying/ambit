// Composition root: owns the setInterval/hashchange/tick() orchestration
// that ties the data layer (state.js) to the router (router.js) and the
// shell chrome (chrome.js). Kept here, not inside state.js or router.js,
// specifically to avoid an import cycle — state.js never imports router.js,
// router.js and every tab import state.js, and app.js is the only file
// that needs both.

import { STATE, POLL_MS, refreshAll, isFormOpen, setFormOpen, formFieldIsFocused } from "./state.js";
import { relTime } from "./format.js";
import { render } from "./router.js";
import { initChrome, updateHealthPill } from "./chrome.js";

function renderDataAsOf() {
  const el = document.getElementById("data-as-of");
  if (!STATE.lastFetchedAt) { el.textContent = ""; return; }
  el.innerHTML = `<span class="live-dot"></span>Live · updated ${relTime(STATE.lastFetchedAt.toISOString())}`;
}

async function tick(force = false) {
  let changed = false;
  try {
    changed = await refreshAll();
  } catch (err) {
    console.error("refresh failed", err);
  }
  updateHealthPill();
  if (force || (changed && !(isFormOpen() || formFieldIsFocused()))) {
    render(tick);
  } else {
    renderDataAsOf(); // still reflect the successful sync time, even with no visible change
  }
}

initChrome();

window.addEventListener("hashchange", () => {
  setFormOpen(false); // leaving the tab — any open form here no longer exists
  render(tick);
});

tick(true);
setInterval(() => tick(false), POLL_MS);
