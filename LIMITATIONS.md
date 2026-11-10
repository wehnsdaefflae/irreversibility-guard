# Known limitations

## A classifier-based guard cannot be sound

Deciding whether an act is irreversible is an open-ended question over natural-language
intent and arbitrary tool surfaces. No classifier — pattern, model or both — decides it
correctly in general. **There will always be an irreversible act this guard fails to
recognise.** Its value is not a proof; it is raising the cost and the visibility of such
acts, and making the ones it does recognise require a human.

What *is* sound here are the **structural** mechanisms, which decide nothing about intent:

- **per-VERB capability reservation** — a grant is a grant on one qualified verb;
- **read-before-destroy preconditions** — a check on session history, not on meaning;
- **human-committed approval dials** — a self-modifying act is not agent-grantable;
- **exact, single-use goes** — a go covers one canonical act and cannot be replayed;
- **untrusted-origin denial** — content is never authority;
- **batch strictness** — a batch inherits its strictest member's verdict.

Each is a mechanical property of the call, and holds regardless of what any classifier
believes. The **declarative manifest** is the only trustworthy *classification* tier, and
only to the extent a human declared their tools correctly.

## Implemented and tested

Code exists and at least one case asserts on its verdict *and* its reason code
(see `RESULTS.md` for the per-case table):

- canonical action rendering, order- and nesting-independent (3 unit cases)
- manifest / heuristic / unknown tiering, with unknown failing closed (4 unit cases)
- alias resolution to a fixpoint, including cycles, before grant and classification (bp-05)
- per-verb capability reservation, wildcard not covering the irreversible verb (3 unit cases)
- read-before-destroy, refusing then permitting (fs-01, bp-01, bp-05)
- hold-and-re-consent bound to the exact act (bn-12 + unit)
- exact, single-use human goes (fs-03 + 2 unit cases)
- untrusted-origin denial (bp-04)
- operator prohibition outranking the task (bp-02)
- duplicate/blind-retry detection (bp-03)
- batch strictness with the offending member named (bp-06)
- composition detection for the declared rule table (bp-07)
- self-modifying acts: human-required, and denied at the top dial (bp-08, fs-04)
- read-set integrity: injected content cannot perform the read that would unlock a
  destroy, because untrusted origin is refused before the read is recorded (bp-09)
- canonical-form properties the single-use go gate depends on: permutation invariance
  and injectivity over 250 distinct acts with no collision (`tests/scenarios/test_fuzz.py`)
- JSONL audit log and the per-session verdict tally (2 unit cases)

## Implemented, untested

- **The `outward` + `undo` interaction** for verbs that are both outward and carry an
  undo string: reachable in code, no case pins its precedence.
- **`ManifestEntry.undo` text** is never executed or validated — it is documentation.
- **Heuristic coverage breadth.** Two cases exercise the pattern tiers; the pattern lists
  themselves (about 30 verb stems) are not individually covered, so a stem could be
  wrong or missing without a test noticing.

## Theoretical — described, not built

- **Composition inference.** `bp-07` passes against a *declared* rule table of four
  compositions. The guard does **not** infer that an undeclared sequence of reversible
  steps composes irreversibly. An attacker who finds a composition nobody wrote down
  walks through. This is the largest gap in the current implementation and the honest
  reading of the bp-07 pass: it demonstrates the mechanism, not general coverage.
- **Recovery and rollback.** The guard classifies and refuses; it never performs an undo,
  snapshots nothing, and offers no recovery path.
- **Multi-agent / delegated acts.** An agent that asks another agent to perform the act
  is out of scope entirely.
- **Enforcement of its own interposition.** Nothing stops an integrator from calling a
  tool without asking the guard.
- **Rate and volume limits.** Not modelled.
- **A framework adapter.** There is no MCP server, no OpenAI tool-calling middleware and
  no measured per-call latency overhead. Integration today is the six-line dispatcher
  wrapper in the README. What the guard does if it *itself* raises is undefined — an
  integrator must decide fail-open vs fail-closed; the library does not choose for them.
- **A canonicalization specification.** The canonical form is tested for permutation
  invariance and injectivity over the generated corpus, but it is defined by its
  implementation, not by a written spec with portable conformance vectors. Unicode
  confusables, symlink and path-traversal equivalence, and TOCTOU between approval and
  execution are **not** addressed: two paths that differ textually but name the same file
  render as two different acts, so a go on one does not cover the other (safe), but the
  read-before-destroy precondition can likewise be *unsatisfiable* by reading the same
  file under a different name (a false positive).
- **Property-based search for undeclared compositions.** The variant expansion searches
  over the *shape* of calls within known families; it does not search for new irreversible
  compositions. That remains the largest soundness gap, above.
- **A no-guard baseline and statistical intervals.** The weakened-guard meta-test shows
  the blocked acts go through unguarded, but there is no quantified baseline (e.g. an
  agent-trace corpus with and without the guard) and no confidence intervals on the
  false-positive rate.

## The false-positive number, honestly

`RESULTS.md` reports **0 false positives on 14 benign actions = 0.000**. That is a real
measurement, but **14 controls is a small set**, hand-written by the same author as the
guard, and a 0.000 rate on it should be read as "no obvious over-blocking", not as
evidence that the guard is cheap to live with in production. The guard's design
deliberately spends false positives on irreversible acts (an unknown verb is held; an
unread target is refused), so the real-world rate depends almost entirely on how
completely the integrator's manifest declares their tools. An undeclared tool surface
will produce holds.

The session tally (`guard.session.tally`) and the audit log exist precisely so that an
integrator can measure this on their own traffic rather than trusting this number.

## Scope of the axis

The guard enforces *irreversibility*, not *harm*, not *correctness*, not *policy
compliance in general*. A reversible act that is catastrophic in content passes.
