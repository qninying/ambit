// ADR-011: real operator authentication for approve/deny. Session token
// storage + decode only — a leaf module with zero internal dependencies, so
// both state.js (attaches the header) and chrome.js (renders the widget)
// can import it without a cycle. The token itself is a per-browser
// convenience (localStorage); the server's own signature verification is
// the actual security boundary, never this module.

const TOKEN_KEY = "ambit_session_token";

export function getSessionToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null; // private-browsing / storage blocked — treat as logged out
  }
}

export function setSessionToken(token) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Session just won't survive a reload this time — not a functional failure.
  }
}

export function clearSessionToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Nothing to clear if storage was never reachable.
  }
}

// Reads the username out of the token's own payload purely for display —
// the payload is signed, not secret, so this is safe to decode client-side,
// but it is NOT a verification step. The server is the only thing that
// actually verifies a session; this just avoids an extra round-trip to
// show "signed in as X" in the header.
function decodeSessionUsername(token) {
  try {
    const [payloadB64] = token.split(".");
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.username === "string" ? payload.username : null;
  } catch {
    return null;
  }
}

export function currentUsername() {
  const token = getSessionToken();
  return token ? decodeSessionUsername(token) : null;
}
