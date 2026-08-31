// Application shell chrome: the app-bar right-side controls (⌘K trigger,
// circuit-breaker health pill, theme toggle, "Acting as" menu). Rendered
// once at startup, not re-rendered on every poll tick (it's chrome, not tab
// content) — only updateHealthPill() runs on every tick, since that's the
// one piece of chrome that reflects live-polled data.

import { STATE } from "./state.js";
import { esc, iconSun, iconMoon } from "./format.js";
import { currentTheme, toggleTheme, initTheme } from "./theme.js";
import { actingAs, setActingAs } from "./session.js";
import { openCommandPalette, initCommandPalette } from "./commandPalette.js";

function renderTopbarControls() {
  const el = document.getElementById("topbar-controls");
  el.innerHTML = `
    <button class="cmdk-trigger" id="cmdk-btn" type="button">Jump to… <kbd>⌘K</kbd></button>
    <span class="health-pill state-closed" id="health-pill"><span class="dot"></span>Store: closed</span>
    <button class="icon-btn" id="theme-toggle-btn" type="button" aria-label="Toggle theme" title="Toggle light/dark theme"></button>
    <div class="acting-as-menu">
      <button class="acting-as-trigger" id="acting-as-btn" type="button">${esc(actingAs())} ▾</button>
      <div class="acting-as-popover" id="acting-as-popover" hidden>
        <label for="acting-as-input">Acting as</label>
        <input id="acting-as-input" value="${esc(actingAs())}" spellcheck="false" />
        <div class="hint">The approver/author identity Ambit records on requests you decide and policies/rules you author. Ambit has no login — this is a free-text field, not a verified identity.</div>
      </div>
    </div>
  `;

  document.getElementById("cmdk-btn").addEventListener("click", () => openCommandPalette());

  const themeBtn = document.getElementById("theme-toggle-btn");
  function syncThemeIcon() { themeBtn.innerHTML = currentTheme() === "dark" ? iconSun() : iconMoon(); }
  syncThemeIcon();
  themeBtn.addEventListener("click", () => { toggleTheme(); syncThemeIcon(); });

  const actingBtn = document.getElementById("acting-as-btn");
  const popover = document.getElementById("acting-as-popover");
  const input = document.getElementById("acting-as-input");
  function closePopover() { popover.hidden = true; document.removeEventListener("click", onOutsideClick); }
  function onOutsideClick(e) { if (!e.target.closest(".acting-as-menu")) closePopover(); }
  actingBtn.addEventListener("click", () => {
    popover.hidden = !popover.hidden;
    if (!popover.hidden) { input.focus(); document.addEventListener("click", onOutsideClick); }
  });
  input.addEventListener("change", () => {
    setActingAs(input.value);
    actingBtn.textContent = `${actingAs()} ▾`;
  });
}

const HEALTH_LABEL = { closed: "Store: closed", open: "Store: open", half_open: "Store: half-open" };

export function updateHealthPill() {
  const pill = document.getElementById("health-pill");
  if (!pill) return;
  const state = STATE.circuitBreaker?.state || "closed";
  pill.className = `health-pill state-${state}`;
  pill.innerHTML = `<span class="dot"></span>${esc(HEALTH_LABEL[state] || state)}`;
}

export function initChrome() {
  initTheme();
  initCommandPalette();
  renderTopbarControls();
  updateHealthPill();
}
