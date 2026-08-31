// Tab metadata only (id/label/icon) — deliberately split out of router.js
// so it can be imported by both router.js (which also needs every tab's
// render function) and commandPalette.js/chrome.js (which need only this)
// without pulling the render functions along and creating an import cycle:
// chrome.js -> commandPalette.js -> (this file, a leaf) rather than
// chrome.js -> commandPalette.js -> router.js -> every tab, including ones
// that need to import chrome.js themselves (e.g. requests.js's auth widget
// refresh after a 401).

import { iconGrid, iconInbox, iconKey, iconShield, iconRedact, iconList, iconPulse } from "./format.js";

export const TABS = [
  { id: "overview", label: "Overview", icon: iconGrid },
  { id: "requests", label: "Requests", icon: iconInbox, badgeKey: "pendingCount" },
  { id: "tokens", label: "Tokens", icon: iconKey },
  { id: "policies", label: "Policies", icon: iconShield },
  { id: "redaction", label: "Redaction Rules", icon: iconRedact },
  { id: "audit", label: "Audit Log", icon: iconList },
  { id: "system", label: "System", icon: iconPulse, badgeKey: "breakerOpen" },
];
