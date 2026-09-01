# ADR-006: In-Memory Persistence Now, Deliberately, With a Same-Interface Graduation Path

**Status:** Implemented (as a deliberate choice) — open item for graduation, tracked explicitly rather than left implicit.
**Owner:** Quincy Nkwain Ninying
**Date:** 2026-08-26 (running theme, STORY-001 through STORY-007)
**Component:** `src/tokenStore.ts`, `src/requestStore.ts`, `src/policy.ts`

---

## Context

Every story so far has flagged the same caveat in its own confidence
assessment: state is in-memory and resets on process restart. This has never
been an accident or an oversight — it's the same "walking skeleton first"
choice made once, at STORY-001, and re-confirmed rather than silently
inherited every story since. This ADR exists so that choice is a recorded
decision with real alternatives weighed, not just a comment that happens to
recur in commit messages.

The precedent for treating this seriously comes directly from CoreOps's own
ADR-005: an in-memory-only audit trail was that project's sharpest trust-
posture finding, precisely because "the record must outlive the process" is
what makes an audit claim actually verifiable. The same reasoning applies here
to every store, not just the audit log — which is why Ambit's audit log
additionally got a tamper-evidence property (ADR-008) even before persistence
itself, since a persisted-but-not-tamper-evident log would just move the same
underlying trust gap to a different location.

## Decision drivers

| Driver | Why it matters here |
|---|---|
| Zero new dependencies, deliberately | This repo has no database dependency today. Adding one is exactly the kind of decision this repo's own conventions call a "deliberate add," not something to slip in as a side effect of a feature story. |
| Walking skeleton first | Get the access-control model correct before choosing infrastructure to durably store it in — the two are separable concerns, and conflating them risks locking in a persistence choice before the data shape has stabilized. |
| Don't hide the tradeoff | A demo that quietly can't survive a restart is worse than one that says so plainly. |

## Options considered

| | **A: A real database now** | **B: In-memory `Map`-backed stores with a portable interface (chosen)** | **C: File-backed (JSONL), matching CoreOps's own ADR-005** |
|---|---|---|---|
| New dependency | Yes | None | None — `node:fs` only |
| Survives a restart | Yes | No | Yes |
| Matches current stage | Premature — schema and access patterns are still actively changing story to story | Yes | Closer, but still a real implementation cost paid before it's clearly needed |
| Blocks the graduation path later | No, but the choice would be made under story-delivery pressure rather than deliberately | No — `get`/`save`/`list` is the same shape a real store would implement | No |

Option A was rejected for the same reason CoreOps's own ADR-005 rejected
SQLite for the audit trail specifically: it's a fine choice in general, but
committing to one now, mid-story, is a bigger and less reversible decision
than the actual immediate problem calls for. Option C is the most likely next
step and is named here deliberately so it doesn't need to be rediscovered —
see "What would change this decision."

## Decision

**Every store (`TokenStore`, `RequestStore`, `PolicyStore`) is in-memory,
`Map`-backed, and exposes only `get`/`save`/`list`/`childrenOf` — a real
backing store could implement the identical interface later without any
caller changing.** This is the same shape ADR-001 already established for a
different reason (single source of truth); persistence is a property that
interface can gain without changing its shape.

## Consequences

**What this requires:** nothing extra today — this is the status quo, made
explicit rather than left implicit.

**What this means in practice:** every demo of this system starts from empty
state after a restart. Fine for a portfolio demo; explicitly not fine for
anything resembling production use, and every story's confidence notes have
said so rather than letting it go unstated.

## What would change this decision

Sustained real usage, or a demo that needs to survive being restarted between
sessions, would justify moving to something like CoreOps's own ADR-005
pattern (append-only JSONL, zero new dependency, rehydrate on start) as the
smallest real step — not a database, unless query needs actually grow beyond
`get`/`list`.

## Update (2026-09-01): the named graduation path, taken

See [ADR-014](ADR-014-persistence-via-append-only-jsonl.md) — exactly the
path this ADR named, taken once ADR-009's other three items were closed.
Every store now supports optional JSONL persistence via `AMBIT_DATA_DIR`,
`get`/`save`/`list` unchanged on every one, live-verified across a real
process restart. This ADR's own reasoning (why in-memory first, what the
next step would look like) is left as-written above rather than rewritten —
it was the accurate record of the decision at the time, and it correctly
predicted its own successor.
