import { STATE } from "./state.js";
import { esc, hashParam, iconGrid, iconInbox, iconKey, iconShield, iconRedact, iconList, iconPulse } from "./format.js";
import { renderOverview } from "./tabs/overview.js";
import { renderRequests } from "./tabs/requests.js";
import { renderTokenList } from "./tabs/tokens/list.js";
import { renderTokenDetail } from "./tabs/tokens/detail.js";
import { renderPolicies } from "./tabs/policies.js";
import { renderRedactionRules } from "./tabs/redactionRules.js";
import { renderAudit } from "./tabs/audit.js";
import { renderSystem } from "./tabs/system.js";

export const TABS = [
  { id: "overview", label: "Overview", icon: iconGrid },
  { id: "requests", label: "Requests", icon: iconInbox, badgeKey: "pendingCount" },
  { id: "tokens", label: "Tokens", icon: iconKey },
  { id: "policies", label: "Policies", icon: iconShield },
  { id: "redaction", label: "Redaction Rules", icon: iconRedact },
  { id: "audit", label: "Audit Log", icon: iconList },
  { id: "system", label: "System", icon: iconPulse, badgeKey: "breakerOpen" },
];

const TAB_COPY = {
  overview: ["Overview", "What's happening across Ambit right now."],
  requests: ["Requests", "Every token request waits here until a human approves or denies it."],
  tokens: ["Tokens", "Every token this process has issued — active, revoked, and their delegation lineage."],
  policies: ["Policies", "Human-authored constraints on what a token can be issued with. Modifying one takes effect on the next issuance checked against it."],
  redaction: ["Redaction Rules", "Field-level constraints on customer-data access — which sensitive fields require which scope to see unredacted."],
  audit: ["Audit Log", "Every allowed, denied, and administrative action — immutable, timestamped."],
  system: ["System", "Health of the Policy & Token Store's circuit breaker, and fault-injection controls for demonstrating fail-closed behavior."],
};

const BADGE_RESOLVERS = {
  pendingCount: () => STATE.requests.length,
  breakerOpen: () => (STATE.circuitBreaker?.state === "open" ? 1 : 0),
};

export function currentTabId() {
  const id = (location.hash || "#overview").slice(1).split("/")[0];
  return TABS.some((t) => t.id === id) ? id : "overview";
}

export function renderNav(activeTabId) {
  const nav = document.getElementById("nav");
  nav.innerHTML = TABS.map((t) => {
    const count = t.badgeKey ? BADGE_RESOLVERS[t.badgeKey]() : 0;
    const badge = count > 0 ? `<span class="nav-badge">${count}</span>` : "";
    return `<button class="topnav-item${t.id === activeTabId ? " active" : ""}" data-tab="${t.id}">${esc(t.label)}${badge}</button>`;
  }).join("");
  nav.querySelectorAll(".topnav-item").forEach((btn) => {
    btn.addEventListener("click", () => { location.hash = `#${btn.dataset.tab}`; });
  });
}

function renderBreadcrumbs(tabId) {
  const el = document.getElementById("breadcrumbs");
  if (tabId === "tokens") {
    const id = hashParam();
    if (id) {
      const token = STATE.tokens.find((t) => t.id === id);
      el.innerHTML = `<a href="#tokens">Tokens</a><span>/</span><span class="crumb-current">${esc(token ? token.subject : id)}</span>`;
      return;
    }
  }
  el.innerHTML = "";
}

let lastRenderedTabId = null;

export function render(tick) {
  const tabId = currentTabId();
  renderNav(tabId);
  renderBreadcrumbs(tabId);
  const [title, desc] = TAB_COPY[tabId];
  document.getElementById("page-title").textContent = title;
  document.getElementById("page-desc").textContent = desc;
  const main = document.getElementById("tab-content");
  // Fade in only when the tab actually changes — background poll refreshes
  // (every 4s) shouldn't flicker the content the user is looking at.
  if (tabId !== lastRenderedTabId) {
    main.classList.remove("fade-in");
    void main.offsetWidth;
    main.classList.add("fade-in");
    lastRenderedTabId = tabId;
  }

  if (tabId === "tokens") {
    const id = hashParam();
    if (id) renderTokenDetail(main, id, tick);
    else renderTokenList(main, tick);
    return;
  }

  const renderers = {
    overview: renderOverview,
    requests: renderRequests,
    policies: renderPolicies,
    redaction: renderRedactionRules,
    audit: renderAudit,
    system: renderSystem,
  };
  renderers[tabId](main, tick);
}
