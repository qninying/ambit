# ADR-008: Hash-Chained, Tamper-Evident Audit Log

**Status:** Implemented — built, unit-tested (including deliberate tampering scenarios), and live-verified over real HTTP.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26
**Component:** `src/auditLog.ts`, `GET /audit-log/verify`, Console Audit Log tab

---

## Context

`AuditLog.entries()` had returned a copy of its internal array since STORY-001,
with a comment explaining that's what "immutable" meant here — callers could
read the trail but not mutate the copy they were handed. That's real, but it's
a narrower guarantee than it sounds: nothing about the design detected or
proved that the *underlying* data hadn't been altered by anything with access
to the process's memory, and nothing let an outside verifier confirm the log
was intact without simply trusting the class's own accessor. For a system
whose entire value proposition rests on a trustworthy audit trail, "immutable"
asserted only by a comment on a method is a real, specific gap — not a
hypothetical one raised for its own sake.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| "Immutable" has to mean something checkable | A property nobody can verify isn't a guarantee, it's a claim. |
| No new dependency | This repo has managed without a cryptography library so far; the fix shouldn't force one in if the built-in platform already covers it. |
| Must report *where* tampering occurred, not just *that* it did | "Something is wrong somewhere in the log" is much less useful to an investigator than "entry `abc-123` doesn't match." |

## Options considered

| | **A: Leave "immutable" as a convention/comment (status quo)** | **B: Sign each entry with a private key** | **C: Hash-chain each entry to the previous one's hash (chosen)** |
|---|---|---|---|
| Detects tampering | No | Yes | Yes |
| New dependency | None | A crypto/signing library, plus key management | None — Node's built-in `crypto` module only |
| Meaningful against this threat model | N/A | Marginal — a private key sitting in the same process as the log doesn't add much over a hash chain if the attacker already has process access | Yes, for the actual threat this addresses (see Consequences for what it does *not* cover) |
| Reports exactly where the chain breaks | N/A | Depends on implementation | Yes, by design — `verifyAuditChain()` returns the first entry id where the link fails |

Option B was seriously considered and rejected specifically because signing
buys little extra for the threat model that actually matters at this stage —
an attacker with write access to the running process's memory (the only
realistic attacker for an in-memory, single-process log) could tamper with a
signing key stored in that same process just as easily as they could tamper
with a hash. Signing earns its cost once the log and the signer are in
different trust domains; that's a real future step, not the problem this
decision closes.

## Decision

**Every `AuditLogEntry` carries `hash` and `previousHash`.** `hash` covers the
entry's own content plus `previousHash` (same principle as a certificate
transparency log). `computeEntryHash()` uses `node:crypto`'s SHA-256 — no new
dependency. `verifyAuditChain(entries)` is a **pure function over any entry
array**, not a method reading private state — this is deliberate: it lets the
real log's `entries()` output be verified, *and* it lets a test construct a
deliberately tampered array (mutate one field, or delete an entry entirely)
and assert exactly which entry id the chain reports as broken, without needing
any backdoor into `AuditLog`'s private state. `GET /audit-log/verify` exposes
this over HTTP, and the Console's Audit Log tab shows a live "chain verified"
badge — the property is demonstrable, not just asserted in a docstring.

## Consequences

**What this detects, tested directly:** a field changed on any single entry
after the fact, and an entry deleted or reordered (caught via the
`previousHash` link even when each remaining entry's own content hash is still
internally self-consistent).

**What this does not cover — stated plainly, not oversold:** an attacker with
enough access to rewrite the *entire* log, in order, could recompute every
downstream hash to match and produce an internally consistent — but entirely
fabricated — chain. A hash chain alone only defends against *partial* or
careless tampering (someone edits one entry without recomputing everything
after it); it does not defend against a fully adaptive attacker with complete
write access and the algorithm in hand. Meaningful protection against that
requires an external anchor — periodically publishing the current chain root
somewhere the attacker doesn't control, or moving the log outside the
single process's own memory (see ADR-006, which already names real
persistence as an open item). This ADR closes the "immutable is unverifiable"
gap; it does not close the "process is fully compromised" gap, and says so
rather than implying otherwise.

## What would change this decision

Real persistence (ADR-006) plus periodic external anchoring of the chain root
would close the remaining gap named above — worth doing together, since an
anchored-but-not-persisted chain would lose everything on restart anyway.
