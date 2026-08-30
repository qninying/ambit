# ADR-010: Policy Selection Moved to Approval Time — Not Requester-Chosen

**Status:** Implemented — fixed, tested (unit + real-HTTP), live-verified against the actual exploit path, and verified in the Console UI.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-30
**Component:** `src/tokenRequest.ts`, `src/server.ts`, `public/console.js`

---

## Context

A full trust-boundary audit — run after all 12 of the platform's stories shipped, at the user's explicit request for "a thorough check... any trust boundaries that are weak" — found a real design flaw that had existed since STORY-007 and gone uncaught through every prior review: `POST /requests` let the *requester* specify `policyId` in their own submission, and `approveRequest()` blindly used whatever the requester had cited when actually issuing the token.

Combined with `POST /policies` being unauthenticated (already tracked under [ADR-009](ADR-009-trust-boundary-hardening-deferred-to-post-platform-phase.md)), the exploit was direct: create a policy with `maxTtlSeconds: 999999999` and a broad `allowedScope`, cite its id on your own request, and the "policy check" becomes a rubber stamp you wrote yourself.

It compounded on the human side. The Console's pending-request card showed only a generic `<span class="badge">policy attached</span>` — no name, no scope, no TTL cap. An approver had no way to see whether the cited policy was a real governance constraint or something the requester invented thirty seconds earlier. This wasn't just a bypass path; it was a false-confidence problem — "policy attached" *looked* like a safety signal and wasn't one, which is arguably worse than no signal at all, since it could make an approver click faster rather than slower.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| A governance control has to be governed by the governor | Policies exist so a human (or a system acting on a human's behalf) can constrain what gets issued. Letting the *subject of the constraint* also choose the constraint defeats the entire premise, independent of whether caller authentication exists yet. |
| Don't wait for ADR-009's full auth phase to fix this | Real caller authentication would help (a verified "policy manager" role could be required to create policies), but this specific flaw — self-citation — is fixable today, standalone, without waiting for that larger bundle. |
| The audit trail has to reflect the real decision-maker | If policy selection moves to the approver, the audit log recording *who approved* has to also record *which policy they applied* — otherwise the fix closes the exploit but leaves the accountability question just as unanswered as before. |

## Options considered

| | **A: Require caller auth before allowing any policyId (defer to ADR-009)** | **B: Validate that the citing subject "owns" the policy somehow** | **C: Move policy selection to approval time entirely (chosen)** |
|---|---|---|---|
| Fixes the exploit without waiting for the full auth phase | No — this is exactly the kind of narrow item ADR-009's "What would change this decision" already anticipated pulling forward | Partially — still requires a notion of policy ownership, which doesn't exist and can't be built honestly without real identity | Yes, immediately |
| Matches how a human approval workflow actually should work | N/A | N/A — policies aren't naturally "owned" by requesters in any real IAM system; approvers or administrators apply them | Yes — this is how policy attachment works in any real access-control system: the approver decides what applies, not the requester |
| New concepts required | None, but blocks on ADR-009 | A policy-ownership model that doesn't exist anywhere else in this domain | None — reuses the existing human-approval step (STORY-003) as the natural point of attachment |

Option B was considered and rejected quickly: inventing a "policy ownership" concept purely to patch this one flaw would be solving a problem this codebase doesn't otherwise have, and still wouldn't stop a requester from citing *someone else's* legitimately-authored-but-inappropriate policy. Option C is a strict improvement with no new concepts and no dependency on ADR-009 landing first.

## Decision

**`POST /requests` no longer accepts `policyId` at all** — `requestToken()`'s own parameter type now structurally excludes it (`Omit<TokenRequest, "policyId">`), and the route silently ignores the field if a client sends one, same as any other unrecognized field. **`approveRequest()` takes `policyId` as its own parameter, supplied by the approver at approval time** (`POST /requests/:id/approve`'s request body), not read from the pending request. The Console's Requests tab now shows a real policy picker (by name, not raw UUID) next to each Approve button, and the old submission-time "Policy (optional)" field and the meaningless "policy attached" badge are both gone.

**Found and closed in the same pass, not left for later**: live-verifying this fix surfaced that the `request_approved` audit entry never recorded which `policyId` had actually governed issuance — true even in the *original*, flawed design. Since the whole point of moving this decision to the approver is to make it accountable, an audit trail that doesn't show which policy was applied would have undercut the fix's own purpose. `policyId` is now part of the `request_approved` entry itself.

## Consequences

**What this requires:** nothing new operationally — the approver picks a policy from ones already created via `POST /policies`, exactly as before; only *when* that choice happens changed.

**What this does not fix:** `POST /policies` itself is still unauthenticated (ADR-009, still fully open) — anyone can still create a policy. What this closes specifically is a requester being able to *force* their own choice of policy onto their own approval; an approver can still, today, pick a bad policy if one exists and they don't notice. That's the same class of risk as an approver clicking Approve on a bad *request* — a human-judgment risk this system has always relied on REQ-002/REQ-013's human-in-the-loop design to catch, not something this fix claims to solve on its own.

## What would change this decision

Once ADR-009's full hardening phase lands (real caller identity, verified roles), a further tightening would be restricting *which* policies a given approver is even allowed to select from — e.g., a compliance-tier approver sees a different policy list than a general operator. That's a real future step, not something this fix's scope covers.
