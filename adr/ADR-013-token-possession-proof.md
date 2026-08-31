# ADR-013: Token Possession Proof — Third and Final Slice of the ADR-009 Hardening Phase

**Status:** Implemented for `POST /tokens/:id/enforce`, `/delegate`, `/access`, `/customer-data/:customerId`. `POST /tokens/:id/revoke` deliberately left open — see Consequences.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-31
**Component:** `src/token.ts`, `src/delegation.ts`, `src/customerDataAccess.ts`, `src/mockEndpointAccess.ts`, `src/tokenRequest.ts`, `src/server.ts`, `sdk/ambitClient.ts`, `public/js/tabs/requests.js`, `public/js/tabs/tokens/{delegate,customerData,detail}.js`

---

## Context

ADR-011 and ADR-012 closed operator and agent-caller authentication. What remained was the gap those two didn't touch: once a token exists, using it required nothing but its `id` — a public UUID visible in `GET /tokens` (unauthenticated), every audit-log entry, and every denial message. `enforceToken`, `delegateToken`, `accessCustomerData`, and `accessMockEndpoint` all looked a token up by that id and, if found, acted on it — the id was simultaneously the token's public identifier and its only bearer credential. Anyone who had ever seen a token's id could enforce, delegate from, or read customer data through it, whether or not they were ever its rightful holder.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| The fix belongs in the primitive, not just the HTTP boundary | ADR-004's own precedent: "policy enforcement lives inside `issueToken()` itself... not a gate a caller could forget to invoke." A possession check bolted onto `server.ts` alone would leave `enforceToken()` itself just as exploitable to any other caller (a test, a future internal service) that reached it directly. |
| No new dependency | `hashPassword`/`verifyPassword` (`src/passwordHash.ts`, built for ADR-011) already do exactly the scrypt hash-and-verify this needs. |
| Fix the information-disclosure side-effect, not just possession | STORY-010's detailed denial messages (real scope, real revocation reason, real timestamps) were being handed to anyone who merely knew an id. Checking possession *before* examining any other detail closes both problems with one ordering decision. |

## Decision

**`Token` gains `secretHash`.** `issueToken()` generates a random 32-byte secret, hashes it, stores only the hash, and returns `{ token, secret }` — the plaintext exists for exactly one return value, same shape as `registerAgentIdentity` (ADR-012).

**`enforceToken(tokenId, providedSecret, action, ...)`** — now async, secret is its second parameter. Order of checks: store lookup (unchanged) → **possession, via `verifyPassword`** → only then `decide()` (revoked/expired/scope). A wrong or missing secret denies with `reasonCode: "invalid_credential"` and a message that discloses nothing else about the token — not even that it exists in some other state. `delegateToken`, `accessCustomerData`, and `accessMockEndpoint` all thread a `providedSecret` through to the same gate; none reimplement the check.

**Delivery of the secret differs by how the token came to exist:**
- **Delegation** is synchronous and already possession-checked (the caller proved they hold the parent) — the child's secret is returned directly in `POST /tokens/:id/delegate`'s response, once.
- **Human-approved issuance** is not synchronous from the requester's point of view — the operator who calls `POST /requests/:id/approve` is not the token's rightful holder, so **`approveRequest()` returns only the `Token`, never the secret**. The secret is held transiently on the `PendingRequest` record (`tokenSecret`, stripped from every public response — `GET /requests/:id` explicitly excludes it) until claimed exactly once via **`POST /requests/:id/token-secret`**, gated by `requireAgentCredential` and checked against the request's own `subject` — so only the same credential that submitted the request can ever retrieve what it produced.

**Console and SDK** got the same treatment ADR-012 established: the demo continues to exercise the real mechanism, not bypass it. `sdk/ambitClient.ts` gained `claimTokenSecret()` (deliberately never retried — a lost response and an already-claimed secret are indistinguishable from a 410, so retrying could make a caller believe a successful claim had failed). The Requests tab gained a "Claim your token" step; the Tokens tab's detail view gained a shared "This token's secret" field feeding both the Delegate and Access-customer-data panels — protected from the poll-render wipe the same way earlier ADRs' pasted-credential fields were, extended here to cover losing focus when a subsequent button click opens a subform.

## What would change this decision

If `POST /tokens/:id/revoke` is ever brought into an authenticated model (a real open item, not opened by this ADR), the question of *whose* authorization revokes a token — the holder's, an operator's, or both — would need answering there, separately from possession proof, since revocation is deliberately not gated the same way here.

## Consequences

**What this closes:** ADR-009 item 3 (token possession proof) for the four routes that actually exercise a token's authority. Combined with the disclosure-ordering fix, a caller with an invalid credential now learns nothing about a token beyond "that credential doesn't work" — closing a related information-disclosure gap STORY-010 had inadvertently left open.

**What this does not close:** `POST /tokens/:id/revoke` remains reachable with no credential at all — deliberately, since revocation is a management action, not a use of the token's own authority, and folding it into this ADR would conflate two different trust questions. There is no revoke/rotate path for a *leaked* token secret specifically (revoking the token itself still works and is the correct response). With this ADR, **all three items ADR-009 originally scoped as the hardening phase (caller authentication, verified approver identity, token possession proof) are closed for the routes each slice targeted** — persistence (item 4) remains the one item explicitly deferred to its own separate phase, per the plan agreed before this phase began.
