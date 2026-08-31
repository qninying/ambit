// Theme persistence + live OS-preference tracking. The actual first-paint
// theme is set synchronously by an inline bootstrap script in
// console.html's <head> (before the stylesheet loads) — this module takes
// ownership of that `data-theme` attribute afterward: it doesn't need to
// set it on load, only keep it correct as the user or OS changes their mind.

const KEY = "ambit.theme";

function storedTheme() {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

function systemPrefersDark() {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

export function setTheme(theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Preference just won't persist across reload — not a functional failure.
  }
}

export function toggleTheme() {
  setTheme(currentTheme() === "dark" ? "light" : "dark");
}

// Only re-resolves from the OS preference while the operator has never
// made an explicit choice — the instant they do, this listener stops
// overriding it (matches storedTheme() being non-null from then on).
export function initTheme() {
  if (typeof window.matchMedia !== "function") return;
  const mql = window.matchMedia("(prefers-color-scheme: dark)");
  const onChange = () => {
    if (storedTheme() === null) applyTheme(systemPrefersDark() ? "dark" : "light");
  };
  if (typeof mql.addEventListener === "function") mql.addEventListener("change", onChange);
}
