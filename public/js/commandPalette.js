// ⌘K command palette — the primary way to move between sections in the
// command-bar-first shell (no persistent sidebar; the top nav links are the
// visible fallback). Opens on Cmd/Ctrl+K or the visible trigger button,
// closes on Escape/outside-click/selection.

import { esc } from "./format.js";
import { TABS } from "./tabsMeta.js";

let overlay = null;
let activeIndex = 0;
let matches = [];

function items() {
  return TABS.map((t) => ({ id: t.id, label: t.label, icon: t.icon }));
}

function filterItems(query) {
  const q = query.trim().toLowerCase();
  if (!q) return items();
  return items().filter((i) => i.label.toLowerCase().includes(q));
}

function renderResults() {
  const el = overlay.querySelector(".cmdk-results");
  if (matches.length === 0) {
    el.innerHTML = `<div class="cmdk-empty">No matching section.</div>`;
    return;
  }
  el.innerHTML = matches.map((item, i) => `
    <div class="cmdk-item${i === activeIndex ? " active" : ""}" data-id="${item.id}" data-index="${i}">
      ${item.icon()}<span>${esc(item.label)}</span>
    </div>
  `).join("");
  el.querySelectorAll(".cmdk-item").forEach((row) => {
    row.addEventListener("mouseenter", () => { activeIndex = Number(row.dataset.index); renderResults(); });
    row.addEventListener("click", () => selectItem(row.dataset.id));
  });
}

function selectItem(id) {
  if (id) location.hash = `#${id}`;
  close();
}

function onKeydown(e) {
  if (e.key === "Escape") { close(); return; }
  if (e.key === "ArrowDown") { e.preventDefault(); activeIndex = Math.min(activeIndex + 1, matches.length - 1); renderResults(); return; }
  if (e.key === "ArrowUp") { e.preventDefault(); activeIndex = Math.max(activeIndex - 1, 0); renderResults(); return; }
  if (e.key === "Enter") { e.preventDefault(); const item = matches[activeIndex]; if (item) selectItem(item.id); }
}

export function openCommandPalette() {
  if (overlay) return;
  matches = items();
  activeIndex = 0;
  overlay = document.createElement("div");
  overlay.className = "cmdk-overlay";
  overlay.innerHTML = `
    <div class="cmdk-box" role="dialog" aria-label="Jump to section">
      <div class="cmdk-input-row"><input id="cmdk-input" placeholder="Jump to a section…" autocomplete="off" /></div>
      <div class="cmdk-results"></div>
    </div>
  `;
  document.body.appendChild(overlay);
  renderResults();
  const input = overlay.querySelector("#cmdk-input");
  input.addEventListener("input", () => { matches = filterItems(input.value); activeIndex = 0; renderResults(); });
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", onKeydown);
  input.focus();
}

export function close() {
  if (!overlay) return;
  document.removeEventListener("keydown", onKeydown);
  overlay.remove();
  overlay = null;
}

export function initCommandPalette() {
  document.addEventListener("keydown", (e) => {
    const isK = e.key === "k" || e.key === "K";
    if (isK && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      openCommandPalette();
    }
  });
}
