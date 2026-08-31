# ADR-012: Agent/API-Caller Authentication — Second Slice of the ADR-009 Hardening Phase

**Status:** Implemented for `POST /requests` only. Every other unauthenticated route remains open — see Consequences.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-31
**Component:** `src/agentIdentity.ts`, `src/server.ts`, `sdk/ambitClient.ts`, `public/console.js`

---

## Context

ADR-011 closed "verified approver identity" for two routes but explicitly left ADR-009 item 1 ("real caller authentication") untouched everywhere. The most obviously exploitable form of that gap: `POST /requests` took `subject` as a plain string in the request body. Any caller could request a token *as anyone* — there was no check that the caller submitting a request for `subject: "finance-bot"` was actually `finance-bot`. This ADR closes that specific gap: request submission now authenticates the caller and derives `subject` from that authentication, never from a client-supplied field.

This is deliberately scoped narrower than "every route now requires agent auth." `POST /requests` is where an unverified `subject` does the most damage (it's the field every downstream policy decision keys off of), so it's the first — and, for this slice, only — route gated this way.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| Structurally real, not cosmetic | Same bar ADR-011 set: `subject` has to come from something the server verified, not from a differently-named field the client still controls. |
| No new dependency | `node:crypto` (`randomBytes`, plus the existing `passwordHash.ts` built for ADR-011) already covers everything needed. |
| O(1) lookup, not "hash every stored secret and compare" | Scrypt hashes are salted by design — two runs of the same secret produce different hashes, so a credential can't be looked up *by* its hash. Something unhashed has to identify *which* record to check before the (slow, deliberately expensive) hash comparison runs. |

## Options considered

| | **A: Shared API key per environment** | **B: mTLS / client certificates** | **C: Per-agent `<id>.<secret>` credential, scrypt-hashed at rest (chosen)** |
|---|---|---|---|
| Ties a request to *one specific agent*, not just "some caller" | No — one shared secret can't distinguish callers | Yes | Yes |
| Matches what Ambit actually is (many distinct agent identities, one simple backend) | Partially | No — cert issuance/rotation infra this system has no other use for | Yes |
| New dependencies / infra | None | Yes — a CA, cert lifecycle | None |
| Lookup cost | O(1), but no per-agent identity | O(1) via cert subject | O(1) — the `id` half is looked up directly; only the `secret` half is scrypt-verified |

Option A was rejected for the same reason a single shared password was rejected in ADR-011 — it can't answer "which agent made this call," only "some agent with the key." Option B was rejected as real infrastructure this system has no other need for, mirroring ADR-011's rejection of a full IdP for the operator side.

## Decision

**`src/agentIdentity.ts`**: `AgentIdentityStore` (fresh-lookup Map, same pattern as every other store in this build — `TokenStore`, `PolicyStore`, etc., per ADR-001). `registerAgentIdentity()` generates a random 32-byte secret, hashes it with the existing `hashPassword()` from ADR-011, and returns the credential **exactly once**, at registration time, as `<id>.<rawSecret>` — the AWS-access-key-style split chosen specifically so authentication can look the record up by `id` (cheap, direct) before paying for the scrypt comparison on `secret` (deliberately expensive), rather than scrypt-hashing every stored secret on every request to find a match. Only `secretHash` is ever persisted; the raw secret exists in memory for the single response that hands it back.

`requireAgentCredential` middleware reads `Authorization: Bearer <id>.<secret>`, calls `authenticateAgent()`, and on success attaches `req.agentIdentity = { subject }`. **`POST /requests` no longer reads `subject` from the body at all** — it's deleted from the accepted fields, same treatment ADR-011 gave `approver`. `subject` comes from `req.agentIdentity.subject`, full stop, even if a client sends a different value in the body (verified directly: `server.test.ts` asserts the derived subject wins over a client-claimed one).

`POST /agent-identities` (registration) and `GET /agent-identities` (listing, metadata only — never `secretHash`, never a credential after the one-time registration response) both require `requireSession` — only a logged-in operator can mint new agent identities, which is itself downstream of ADR-011.

**SDK** (`sdk/ambitClient.ts`): `RequestTokenParams.subject` removed entirely — the SDK can't offer a parameter the server will now ignore. `AmbitClientConfig.agentCredential` added; `requestToken()` fails fast client-side (`AmbitClientError`, status 0, before any network call) if no credential is configured, so a misconfigured caller gets an immediate, actionable error instead of a bare 401 to reverse-engineer.

**Console** (`public/console.js`): the "submit a test request" panel — which stands in for the SDK in the demo — now requires a real, registered agent credential pasted into a field, with a "register a new test agent" sub-form next to it (using the operator's own session to call `POST /agent-identities`) so the demo stays fully functional without secretly bypassing the mechanism it exists to exercise. Live verification during this work caught a real gap in that sub-form: the credential field is filled programmatically after registration, and the console's poll-safety guard (`formFieldIsFocused()`, from earlier work) only protects fields the *operator* has focused by typing — a background poll tick could silently wipe the just-filled credential before the operator got to it. Fixed by explicitly focusing the field after filling it, so it gets the same protection a hand-typed field would.

## Consequences

**What this actually closes:** `POST /requests` now has a real, verified caller identity, and `subject` can no longer be spoofed by the client on that route. That's ADR-009 item 1, for this one route.

**What this does NOT close — stated plainly:** every other mutating route — `POST /tokens/:id/revoke`, `POST /policies`, `PATCH /policies/:id`, `POST /redaction-rules`, `POST /tokens/:id/delegate` — remains completely unauthenticated. Token possession proof (item 3) and real persistence (item 4) are untouched. There is also no authorization model yet beyond "this credential belongs to this subject" — an authenticated agent isn't currently restricted from requesting scopes unrelated to its own role; that's a policy-layer concern, not an authentication one, and stays out of scope here.

## What would change this decision

If agent identities ever needed to be revoked or rotated without re-registering (an agent's secret leaks, or an agent is decommissioned), `AgentIdentityStore` would need a `revoke`/`delete` path and `authenticateAgent()` would need to reject a revoked identity even with a still-valid secret. That's a real, foreseeable gap this slice does not close — noted here rather than silently deferred.
