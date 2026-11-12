# Known limitations

## A classifier-based guard cannot be sound

Deciding whether an act is irreversible is an open-ended question over natural-language
intent and arbitrary tool surfaces. No classifier — pattern, model or both — decides it
correctly in general. **There will always be an irreversible act this guard fails to
recognise.** Its value is not a proof; it is raising the cost and the visibility of such
acts, and making the ones it does recognise require a human.

### What "sound" means in this repository

The word is used in one fixed sense throughout, and it is worth stating because it is
narrower than it looks:

> A mechanism is **sound** here if its verdict is a decidable property of the call and
> the session record — so for every input it either holds or it does not, with no
> judgment about what the act *means* or what the user *intended*. Equivalently: two
> deployers running the same mechanism on the same call and the same session always get
> the same verdict, and that verdict can be checked by reading the code and the audit
> log, without agreeing about intent.

Three things that sense of "sound" does **not** claim, and that no mechanism in this
repository claims:

1. **Not completeness.** A sound mechanism stops the acts it is *given*. Per-verb
   reservation stops `mail:send` because someone declared `mail:send` outward; it says
   nothing about the verb nobody declared.
2. **Not correctness of the inputs.** Soundness is conditional on what the integrator
   supplies — the manifest, the never-list, and the `origin` field, none of which the
   guard can verify. Garbage declarations give sound verdicts about the wrong world.
3. **Not security against a host-level attacker.** Everything here is in-process advice
   to a dispatcher. An agent that can write the policy object, patch the module or call
   the tool directly is outside the model entirely (see `THREAT_MODEL.md`).

So "sound (structural)" in the mechanism table means *decidable and intent-free*, not
*sufficient*. The classifier tiers are marked unsound because their verdict depends on
an open-ended judgment about an act's meaning; the structural gates are marked sound
because theirs does not. Neither marking is a safety guarantee.

What *is* sound in that sense are the **structural** mechanisms, which decide nothing about intent:

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
- fail-closed provenance: an irreversible act whose `origin` was never declared is
  `REQUIRE_HUMAN`, re-consent does not unblock it, a human go does, reversible acts are
  unaffected, and `trust_undeclared_origin=True` restores the old behaviour (1 unit case,
  four assertions). What this does **not** do: verify provenance. `origin` is still
  supplied by the caller, so an integrator who writes `origin="agent"` on content-echoed
  calls defeats it exactly as before — the change moves the failure from a silent default
  to a written assertion, which is weaker than a check and stronger than nothing.
- alias resolution to a fixpoint, including cycles, before grant and classification (bp-05)
- per-verb capability reservation, wildcard not covering the irreversible verb (3 unit cases)
- read-before-destroy, refusing then permitting (fs-01, bp-01, bp-05)
- hold-and-re-consent bound to the exact act (bn-12 + unit)
- exact, single-use human goes (fs-03 + 2 unit cases)
- untrusted-origin denial (bp-04)
- operator prohibition outranking the task (bp-02)
- duplicate/blind-retry detection (bp-03)
- batch strictness with the offending member named (bp-06)
- **composite irreversibility DERIVED, not listed** (`guard/taint.py`): content identity,
  provenance (agent-authored vs pre-existing, unknown failing closed as pre-existing) and
  a declarative per-verb effect map, so a hazard created several steps earlier on a
  *different* location is still found — bp-07, bp-10, and 5 clause-level cases in
  `tests/scenarios/test_composition_search.py` (surviving copy defeats the finding;
  agent-authored content is exempt; the cross-location backup-then-destroy case a pair
  table structurally cannot express)
- **manifest fidelity** (bp-11): an act *declared* reversible whose declared undo does not
  hold for this target — a `create` onto an occupied location — is caught rather than
  trusted. **This case was found by `guard/search.py`, not by the author**
- **the search property itself**: in the deployable configuration no sequence up to depth 3
  both passes the guard end to end and loses pre-existing content (184 such sequences under
  the old pair table, 0 now — `RESULTS.md`, `tests/search-findings.json`). The test states
  **Two corrections an independent reviewer forced on 2026-11-12, both of which this file
  previously got wrong:** (1) the test's docstring called the property "vacuous — the
  ordinary gates stop these acts before composition is consulted", and the findings file
  refutes that in the same breath: with those same gates ON, table mode reports **184**
  sequences that pass end to end and lose content. The gates do *not* pre-empt them; the
  composition mechanism is what accounts for the difference, and the word "vacuous" was
  simply wrong. (2) The 184 → 0 comparison is **confounded**: `Policy(composition="table")`
  gates the manifest-fidelity check as well, so selecting it switches off *two* mechanisms,
  and an unknown share of the 184 is fidelity rather than taint closure — the findings
  file's own `gates_on` exemplar (`fs:read /data/a ; fs:copy /data/b`) is a fidelity catch.
  Read 184 → 0 as what the closure **and** the fidelity check buy together; the search
  does not separate them
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
- **The limits the derived taint closure brings with it.** `guard/taint.py` replaced a
  four-row blocklist with a mechanism, which moves the unsoundness rather than removing
  it. Specifically, and none of these is fixed:
  - **The effect map is a declaration.** A verb whose real effect differs from its
    declared effect is misjudged exactly as a mis-declared manifest entry is. bp-11 is
    one such mismatch caught *structurally*; the general case is not solvable by
    declaration.
  - **Provenance is session-local.** Content written by an *earlier* session reads as
    pre-existing. That fails closed (over-blocking, not under-blocking), but it means a
    long-lived agent accumulates false positives that no set measured here can show:
    both the 14 hand-written controls and the 150 independently generated benign calls
    are single-session, so the published 0.187 is a *floor* for a long-lived agent, not
    an estimate of its steady state.
  - **"A copy exists" is tracked structurally, not verified.** The closure believes a
    copy survives because a copy-style act was allowed; it never checks storage. A copy
    that something outside the guard removed still counts as a survivor — an
    under-block, and the most dangerous assumption in the module.
  - **The search is bounded and tiny.** Exhaustive to depth 3 over 7 verbs × 2 locations
    = 2940 sequences. A 4-step hazard, a third location, or any verb outside that
    alphabet is unsearched. "0 violations" means *0 in that box*, not a proof.
- **A general soundness argument.** The closure derives composite irreversibility from
  declared effects; it does not and cannot establish that the derivation is complete.
- **Generalisation beyond the manifest's own vocabulary.** The external evaluation
  (below) measures the heuristic and fail-closed tiers on 85 foreign verbs. It does not
  measure the manifest tier on a foreign surface, because that tier is only as good as
  the integrator's declarations and no benchmark can supply those for them.

## The false-positive number, honestly

**Read 0.187, not 0.000.**

`RESULTS.md` reports two false-positive rates and they disagree by an order of magnitude:

| set | rate | 95% CI | who wrote it |
|---|---|---|---|
| 14 hand-written benign controls | 0.000 | 0.000–0.215 | the guard's author |
| 150 independently generated benign agent calls | **0.187** | 0.132–0.257 | an independent model |
| 45 reversible AgentHarm functions | **0.600** | 0.455–0.730 | UK AISI benchmark + independent labels |

The 0.000 is a real measurement of a set that could not have shown the cost: every verb
in it is one the author also declared in the manifest. The moment the benign traffic
contains verbs the manifest does not declare — which is what an integrator's real
surface looks like on day one — the fail-closed rule holds them, and the rate goes to
0.187 on ordinary traffic and 0.600 on a wholly foreign surface. **Every single false
positive in both external sets comes from the fail-closed rule for undeclared verbs**
(asserted in `tests/scenarios/test_external_eval.py`), not from a misjudgment by the
heuristic tier, which made **0 false positives on the 18 foreign verbs it could read**.

So the cost is not a defect to be tuned away; it is the price of the design's one
non-negotiable rule, and it is paid down by declaring tools, not by weakening the rule.
An integrator with a complete manifest approaches the first row; one who declares
nothing gets the third. That is the trade to budget for, and the numbers above are what
to budget with.

Two further honesties about the zero false-negative rate in the same table: roughly half
of it (the 45 verbs no tier could read, among them 18 irreversible ones) is fail-closed refusing verbs it cannot read
rather than any skill at recognising them, and the whole external evaluation grants the
agent the exact verb it asks for, so per-verb capability reservation — the soundest
mechanism in the guard — is deliberately switched out of the way and contributes nothing
to those numbers. A deployment that uses it is safer than this measurement shows, and a
deployment facing verbs the heuristic tier reads *wrongly* is less safe.

The session tally (`guard.session.tally`) and the audit log exist precisely so that an
integrator can measure this on their own traffic rather than trusting this number.

## Scope of the axis

The guard enforces *irreversibility*, not *harm*, not *correctness*, not *policy
compliance in general*. A reversible act that is catastrophic in content passes.
