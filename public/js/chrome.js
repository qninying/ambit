// Application shell chrome: the app-bar right-side controls (⌘K trigger,
// circuit-breaker health pill, auth widget, theme toggle, "Acting as" menu).
// Rendered once at startup, not re-rendered on every poll tick (it's chrome,
// not tab content) — this is what protects the login/acting-as popovers
// from a background refresh wiping mid-typed input, the same class of bug
// ADR-011 had to specifically guard against in the pre-redesign console.
// updateHealthPill() and updateAuthWidget() are the two explicit,
// event-triggered exceptions: the former runs on every poll tick (it
// reflects live-polled data), the latter only after a login/logout/401.

import { STATE, postJson } from "./state.js";
import { esc, iconSun, iconMoon } from "./format.js";
import { currentTheme, toggleTheme, initTheme } from "./theme.js";
import { actingAs, setActingAs } from "./session.js";
import { currentUsername, setSessionToken, clearSessionToken } from "./auth.js";
import { openCommandPalette, initCommandPalette } from "./commandPalette.js";

// Set by initChrome(tick) — a runtime reference passed in from app.js, not
// a static import of router.js/app.js, specifically to avoid an import
// cycle (chrome.js is imported by requests.js for updateAuthWidget(), so
// chrome.js importing anything that imports requests.js back would cycle).
// Called after login/logout so tab content depending on auth state (e.g.
// the Requests tab's "not signed in" banner) refreshes immediately instead
// of waiting for the next poll.
let refreshTick = null;

function renderTopbarControls() {
  const el = document.getElementById("topbar-controls");
  el.innerHTML = `
    <button class="cmdk-trigger" id="cmdk-btn" type="button">Jump to… <kbd>⌘K</kbd></button>
    <span class="health-pill state-closed" id="health-pill"><span class="dot"></span>Store: closed</span>
    <div class="auth-menu" id="auth-menu"></div>
    <button class="icon-btn" id="theme-toggle-btn" type="button" aria-label="Toggle theme" title="Toggle light/dark theme"></button>
    <div class="acting-as-menu">
      <button class="acting-as-trigger" id="acting-as-btn" type="button">${esc(actingAs())} ▾</button>
      <div class="acting-as-popover" id="acting-as-popover" hidden>
        <label for="acting-as-input">Acting as</label>
        <input id="acting-as-input" value="${esc(actingAs())}" spellcheck="false" />
        <div class="hint">The author identity Ambit records on policies and redaction rules you create — those routes have no login (ADR-009). Approving or denying a request uses your real signed-in identity instead, not this field.</div>
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

  renderAuthWidget();
}

const HEALTH_LABEL = { closed: "Store: closed", open: "Store: open", half_open: "Store: half-open" };

export function updateHealthPill() {
  const pill = document.getElementById("health-pill");
  if (!pill) return;
  const state = STATE.circuitBreaker?.state || "closed";
  pill.className = `health-pill state-${state}`;
  pill.innerHTML = `<span class="dot"></span>${esc(HEALTH_LABEL[state] || state)}`;
}

// ADR-011: real operator authentication for approve/deny. Rebuilds only the
// #auth-menu sub-tree, never the whole control row, and only in response to
// an explicit login/logout/401 — never from the poll timer, so a
// mid-typing login popover can never be wiped out from under an operator.
export function updateAuthWidget() {
  renderAuthWidget();
}

function renderAuthWidget() {
  const el = document.getElementById("auth-menu");
  if (!el) return;
  const username = currentUsername();

  if (username) {
    el.innerHTML = `<button class="auth-trigger" id="auth-btn" type="button">Signed in as ${esc(username)} ▾</button>
      <div class="auth-popover" id="auth-popover" hidden>
        <div class="auth-status-row"><span>Signed in as <strong>${esc(username)}</strong></span></div>
        <button class="btn btn-secondary btn-sm mt-2" id="auth-logout" style="width:100%;">Log out</button>
      </div>`;
    wireAuthPopoverToggle();
    document.getElementById("auth-logout").addEventListener("click", () => {
      clearSessionToken();
      renderAuthWidget();
      if (refreshTick) refreshTick(true);
    });
    return;
  }

  el.innerHTML = `<button class="auth-trigger signed-out" id="auth-btn" type="button">Log in</button>
    <div class="auth-popover" id="auth-popover" hidden>
      <label for="auth-username">Username</label>
      <input id="auth-username" placeholder="username" autocomplete="username" />
      <label for="auth-password">Password</label>
      <input id="auth-password" type="password" placeholder="password" autocomplete="current-password" />
      <button class="btn btn-primary btn-sm" id="auth-submit">Log in</button>
      <div class="toast" id="auth-toast"></div>
      <div class="hint">Required to approve or deny requests (ADR-011). Everything else in this console stays unauthenticated.</div>
    </div>`;
  wireAuthPopoverToggle();
  const submit = async () => {
    const uname = document.getElementById("auth-username").value;
    const password = document.getElementById("auth-password").value;
    const toast = document.getElementById("auth-toast");
    try {
      const { token } = await postJson("/auth/login", { username: uname, password });
      setSessionToken(token);
      renderAuthWidget();
      if (refreshTick) refreshTick(true);
    } catch (err) {
      toast.textContent = err.message;
      toast.className = "toast error";
    }
  };
  document.getElementById("auth-submit").addEventListener("click", submit);
  document.getElementById("auth-password").addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
}

function wireAuthPopoverToggle() {
  const btn = document.getElementById("auth-btn");
  const popover = document.getElementById("auth-popover");
  function close() { popover.hidden = true; document.removeEventListener("click", onOutsideClick); }
  function onOutsideClick(e) { if (!e.target.closest(".auth-menu")) close(); }
  btn.addEventListener("click", () => {
    popover.hidden = !popover.hidden;
    if (!popover.hidden) {
      document.addEventListener("click", onOutsideClick);
      const firstInput = popover.querySelector("input");
      if (firstInput) firstInput.focus();
    }
  });
}

export function initChrome(tick) {
  refreshTick = tick;
  initTheme();
  initCommandPalette();
  renderTopbarControls();
  updateHealthPill();
}
