# Known limitations

## A classifier-based guard cannot be sound

A guard built on a classifier can't be sound, in the sense that its verdict can't be decided from the call and the session record without a judgment of intent. Whether an act is irreversible is an open-ended question over natural-language intent and arbitrary tool surfaces. A classifier doesn't decide that correctly in general, whether it uses patterns, a model or both. This guard always fails to recognise some irreversible act. The guard's value isn't a proof. It raises the cost and the visibility of irreversible acts. Any irreversible act it does recognise requires a human.

### What "sound" means in this repository

This project uses "sound" in one fixed sense throughout the repository. That sense is narrower than the everyday meaning of the word. It leaves out three things. Those three aren't claimed for the mechanisms in the repository either.

> A mechanism is sound here if its verdict is a decidable property of the call and the session record. For every input that property either holds or it doesn't. The verdict doesn't involve any judgment about what the act means or what the user intended. Put another way, two deployers who run the same mechanism on the same call in the same session always get the same verdict. Equivalently, the verdict can be checked by reading the code and the audit log, without any agreement about intent.

1. **Not completeness.** A sound mechanism stops the acts it's given. For example, per-verb reservation stops `mail:send` because someone declared `mail:send` outward. It doesn't cover a verb if nobody declared it.
2. **Not correctness of the inputs.** The integrator supplies the manifest, the never-list and the `origin` field. Soundness depends on those inputs. The guard can't verify any of them. With wrong declarations the verdicts are still sound, but they're about a situation other than the real one.
3. **Not security against a host-level attacker.** Everything in the repository is in-process advice to a dispatcher. An agent is entirely outside the threat model in `THREAT_MODEL.md` if it can write the policy object, patch the module or call the tool directly.

In the mechanism table "sound (structural)" means decidable and intent-free. It doesn't mean sufficient. The table marks the classifier tiers unsound because their verdict depends on an open-ended judgment about what an act means. The table marks the structural gates sound because their verdict doesn't depend on any judgment about what an act means. A "sound" marking isn't a safety guarantee. An "unsound" marking isn't one either. In this sense the structural mechanisms are the sound ones. They don't decide anything about intent.

- **Per-VERB capability reservation.** Each grant is on one qualified verb.
- **Read-before-destroy preconditions.** The check runs on the session history, not on meaning.
- **Human-committed approval dials.** A human commits the approval setting on these dials. The agent can't grant a self-modifying act.
- **Exact, single-use goes.** A human approves one canonical act with each go. The go can't be replayed.
- **Untrusted-origin denial.** Content never counts as authority.
- **Batch strictness.** A batch inherits the verdict of its strictest member.

Each of these is a mechanical property of the call. They hold regardless of what any classifier believes. The declarative manifest is the only trustworthy classification tier. It's only trustworthy as far as a human declared their tools correctly.

## Implemented and tested

An item goes on this list when its code exists and at least one case asserts on its verdict and its reason code. The per-case table is in `RESULTS.md`.

- Canonical action rendering is order-independent and nesting-independent. It has 3 unit cases.
- Manifest, heuristic and unknown tiering has 4 unit cases. Unknown fails closed: the guard treats it as the restrictive case.
- Fail-closed provenance returns `REQUIRE_HUMAN` for an irreversible act if its `origin` was never declared. Re-consent doesn't unblock that act. A human go does. It doesn't affect reversible acts. `trust_undeclared_origin=True` restores the old behaviour. It has a unit case with four assertions. Fail-closed provenance doesn't verify provenance. The caller still supplies `origin`. An integrator still defeats it if they write `origin="agent"` on calls that echo content, the same as before the change. The change moves the failure from a silent default to a written assertion. A written assertion is weaker than a check and stronger than nothing.
- Alias resolution reaches a fixpoint, cycles included. It runs before the grant and before classification. Case bp-05 covers it.
- Under per-verb capability reservation a wildcard doesn't cover the irreversible verb. Three unit cases test that.
- Read-before-destroy first refuses and then permits. Cases fs-01, bp-01 and bp-05 cover it.
- Hold-and-re-consent pauses an act and waits for re-consent. The hold is bound to the exact act. Case bn-12 covers it, along with unit cases.
- Exact, single-use human goes have case fs-03 and 2 unit cases.
- Untrusted-origin denial has case bp-04.
- An operator prohibition outranks the task. Case bp-02 covers that.
- Duplicate and blind-retry detection is in case bp-03.
- Batch strictness names the offending member. Case bp-06 covers it.
- **Composite irreversibility DERIVED, not listed** (`guard/taint.py`). The guard derives composite irreversibility from content identity, provenance and a declarative per-verb effect map. Provenance is either agent-authored or pre-existing. The guard fails closed if it doesn't know the provenance. It counts that content as pre-existing. The guard finds a hazard that was created several steps earlier on a different location. Cases bp-07 and bp-10 cover it, along with 5 clause-level cases in `tests/scenarios/test_composition_search.py`. The clause-level cases cover a surviving copy defeating the finding, agent-authored content being exempt and a backup-then-destroy across locations. Structurally, the old pair table can't hold that cross-location case.
- **Manifest fidelity** (bp-11). Some acts are declared reversible, but their declared undo doesn't hold for this target. Manifest fidelity catches those acts instead of trusting the declaration. One example is a `create` onto an occupied location. `guard/search.py` found this case, not manual review.
- **The search property itself.** In the deployable configuration the search found 0 sequences up to depth 3 that both pass the guard end to end and lose pre-existing content. Under the old pair table the search observed 184 such sequences. Now there are 0. Both counts are in `RESULTS.md` and `tests/search-findings.json`. An independent reviewer forced two corrections on 2026-11-12. Before then, this file got both wrong. First, the reviewer corrected the test docstring. The docstring had the word "vacuous" for the property, with the reason "the ordinary gates stop these acts before composition is consulted". The findings file holds the refutation. With the same gates on, table mode reports 184 sequences that pass end to end and lose content. The ordinary gates don't pre-empt those 184 sequences. The composition mechanism accounts for the difference between 184 and 0. "Vacuous" was the wrong word. Second, the reviewer found the comparison of 184 with 0 confounded. `Policy(composition="table")` also gates the manifest-fidelity check, so selecting it switches off two mechanisms. Some of the 184 come from the fidelity check, not from the taint closure in `guard/taint.py` that derives composite irreversibility. How many is not known. The findings file has a `gates_on` exemplar, `fs:read /data/a ; fs:copy /data/b`. That one is a fidelity catch. The drop from 184 to 0 is the gain of taint closure and the fidelity check together. The search doesn't separate their contributions.
- Self-modifying acts require a human and get denied at the top dial. Cases bp-08 and fs-04 cover them.
- Under read-set integrity, injected content can't perform the read that would unlock a destroy, because the guard refuses its untrusted origin before the read gets recorded. Case bp-09 covers it.
- The single-use go gate needs the canonical form to be permutation-invariant and injective. Over 250 distinct acts no collision was found. The tests are in `tests/scenarios/test_fuzz.py`.
- The JSONL audit log and the per-session verdict tally have 2 unit cases.
- **A real agent driving the guard.** In `scripts/eval_agent_loop.py` a live model picked its own calls from the 85 functions in AgentHarm's tool surface, for up to 8 steps per episode. Every call the model proposed got intercepted before it reached a stubbed dispatcher. 40 episodes ran in each of three evaluation conditions. The agent ran unguarded in one of them and guarded in another. Unguarded, it executed 18 of 30 irreversible target calls. With the guard it executed 0 of the irreversible target calls. The transcript of all 120 episodes is checked in. Nine test cases in `tests/scenarios/test_agent_loop.py` re-derive the numbers offline. What that result costs is in the section on the benign agent below, and it is not hidden here.

## Implemented, untested

- **The `outward` + `undo` interaction.** It applies to verbs that are outward and also carry an undo string. It's reachable in the code. This project hasn't pinned its precedence with a case.
- **`ManifestEntry.undo` text.** The guard never executes or validates it. It's documentation.
- **Heuristic coverage breadth.** Two cases exercise the pattern tiers. The pattern lists hold about 30 verb stems. The stems aren't tested individually. A stem could be wrong or missing. The tests wouldn't notice.

## Theoretical: described, not built

- **Recovery and rollback.** The guard classifies and refuses. It never performs an undo, doesn't snapshot anything and doesn't offer a recovery path.
- **Multi-agent / delegated acts.** An agent asking another agent to perform the act is treated as entirely out of scope.
- **Enforcement of its own interposition.** An integrator can call a tool without asking the guard.
- **Rate and volume limits.** The guard doesn't model rate or volume limits.
- **A framework adapter.** The project doesn't have an MCP server or OpenAI tool-calling middleware. The per-call latency overhead hasn't been measured. Integration currently goes through a six-line dispatcher wrapper in the README. The guard's behaviour when the guard itself raises hasn't been defined. The integrator has to decide between fail-open and fail-closed. The library doesn't make that choice for them.
- **A canonicalization specification.** The canonical form has been tested for permutation invariance and injectivity over a generated corpus. The implementation defines it. The project doesn't have a written spec with portable conformance vectors. Unicode confusables, symlink and path-traversal equivalence, and TOCTOU between approval and execution aren't handled. Two textually different paths can name the same file. The guard renders them as two different acts. A go on one of them doesn't cover the other. That's safe. The read-before-destroy precondition can be unsatisfiable when the same file was read under a different name. That's a false positive.
- **The limits the derived taint closure brings with it.** This project replaced a four-row blocklist with a mechanism in `guard/taint.py`. The replacement moves unsoundness and doesn't remove it. This project hasn't fixed any of these limits.
  - **The effect map is a declaration.** The guard misjudges a verb if its real effect differs from its declared effect. That's the same as with a mis-declared manifest entry. Case bp-11 is such a mismatch. The guard catches that one structurally. The general case can't be solved by declaration.
  - **Provenance is session-local.** The closure reads content as pre-existing when an earlier session wrote it. It fails closed, so the error is over-blocking, not under-blocking. A long-lived agent accumulates false positives. Those false positives can't appear in the sets measured here. The 14 hand-written controls and the 150 independently generated benign calls are all single-session. The published 0.187 is a floor for a long-lived agent, not an estimate of its steady state.
  - **"A copy exists" is tracked structurally, not verified.** The closure treats a copy as surviving because a copy-style act was allowed. It never checks storage. A copy still counts as a survivor after something outside the guard removes it. That's an under-block. This assumption is the most dangerous one in the module.
  - **The search is bounded and tiny.** It's exhaustive to depth 3 over 7 verbs and 2 locations, 2940 sequences in all. It doesn't cover a 4-step hazard, a third location or any verb outside that alphabet. "0 violations" means 0 within that searched space. That isn't a proof.
- **A general soundness argument.** The closure derives composite irreversibility from declared effects. It doesn't and can't establish that the derivation is complete.
- **Generalisation beyond the manifest's own vocabulary.** The external evaluation measures the heuristic and fail-closed tiers on 85 foreign verbs and doesn't measure the manifest tier on a foreign surface. It can't, because the manifest tier is only as good as the integrator's declarations. A benchmark can't supply declarations for the integrator.

## The false-positive number, honestly

The figure to use is 0.187, not 0.000. `RESULTS.md` has two false-positive rates an order of magnitude apart.

| Set | Rate | 95% CI | Who wrote it |
|---|---|---|---|
| 14 hand-written benign controls | 0.000 | 0.000–0.215 | The guard's author |
| 150 independently generated benign agent calls | 0.187 | 0.132–0.257 | An independent model |
| 45 reversible AgentHarm functions | 0.600 | 0.455–0.730 | UK AISI benchmark, with independent labels |

The 0.000 is a real measurement. The false-positive cost couldn't appear in the 14 controls, because every verb in them was also declared in the manifest. In benign traffic the fail-closed rule holds a verb if the manifest doesn't declare it. On day one the manifest doesn't declare some of the verbs on an integrator's real surface. A rate of 0.187 was observed on ordinary traffic and 0.600 on a wholly foreign surface. Every false positive in both external sets came from the fail-closed rule. In each case the manifest didn't declare the verb. `tests/scenarios/test_external_eval.py` asserts that. The heuristic tier didn't cause any of the false positives in the external sets. It could read 18 foreign verbs and had 0 false positives on them.

The false-positive cost isn't a defect that tuning removes. It's the price of the design's one non-negotiable rule. Declaring tools reduces the cost. Weakening the rule doesn't. With a complete manifest an integrator approaches the first-row rate. An integrator gets the third-row rate if they declare nothing. Integrators should budget for this cost as a trade. The numbers in the table are the basis for that budget.

Roughly half of the zero false-negative rate in the same table comes from fail-closed refusals, not from skill at recognising verbs. That half covers 45 verbs. The guard couldn't read those 45, so the fail-closed rule refused them. Of the 45, 18 are irreversible. Per-verb capability reservation is the soundest mechanism in the guard. It was deliberately bypassed in the external evaluation, because the whole evaluation grants the agent the exact verb it asks for. The reservation doesn't contribute anything to those numbers. A deployment would be safer than what was measured if it used per-verb capability reservation. Verbs that the heuristic tier reads wrongly would make a deployment less safe than what was measured. The session tally at `guard.session.tally` and the audit log are there so an integrator can measure false positives on their own traffic instead of trusting this number.

### What the guard costs a benign agent, measured with the agent running

The false-positive number in the section before this one is a per-call figure. The cost to an agent that has to finish a task is higher than that figure, because one refusal in a chain of calls ends the task. That task-level cost was measured directly, with a live agent in the loop, and it is worse than it looks from the per-call figure.

The agent ran on AgentHarm's 85-function surface. The guard's manifest declares none of those 85 verbs. Benign task completion was 0.35 with no guard and 0.00 with the guard. A trivial baseline that refuses the whole tool surface also came out at 0.00. On an entirely undeclared surface the guard added no completions over that baseline.

Nearly every refusal the guard returned was the hold `hold.unknown_verb_fails_closed`. That hold comes back before consent gets consulted, so the agent cannot clear it. Reversible calls still ran under the guard, and that is the only measured difference between the guard and the trivial baseline: the guard let 80 of 202 proposed calls run, while under the trivial baseline 0 of 160 proposed calls ran.

The deployable claim made for this guard covers a surface with a manifest. The agent-loop evaluation above does not test that kind of surface, because declaring the 85 functions would give the evaluation the answers it is meant to test.

**The curve this section used to call missing was measured on 2026-11-14, and measuring it showed the 0.00 above to be the wrong number to quote.** 19 of the 20 AgentHarm benign tasks require an irreversible act of their own, usually an outward one. The `HOLD_IRREVERSIBLE` dial cannot complete such a task without a person, at any coverage. So the no-human completion rate measures the dial, not the manifest: swept at 0%, 25%, 50%, 75% and 100% coverage it reads 0.00 at every single coverage. The 0.00 against 0.35 in this section is accurate and was honestly reported, and it does not mean what this document took it to mean.

The replacement measurement puts a reviewer in the loop, which is what the dial assumes, and sweeps coverage on both halves of the evaluation. With declarations synthesized from the independent labels, the static benign false-positive rate falls 0.600 → 0.447 → 0.281 → 0.144 → 0.000 across those coverages, while the strict false-negative rate stays 0.000. With a reviewer, real-agent benign completion rises 0.10 → 0.10 → 0.20 → 0.20 → 0.30, reaching the unguarded arm's own 0.30, while every arm still executes 0/30 of the harmful target calls. Escalated decisions rise from 27 to 48. Raw records: `tests/coverage-eval.json`, `tests/agent-loop-coverage.json`, `tests/agent-loop-coverage-human.json`; re-derived offline by `tests/scenarios/test_coverage.py`.

What that curve does **not** establish, stated here rather than in the results:

- **The declarations are correct by construction.** They are synthesized from the ground-truth labels, so the curve is an upper bound: what coverage buys an integrator who declares accurately. Nothing here measures an integrator's ability to label their own tools, which is the step most likely to fail.
- **A wrong declaration is worse than no declaration.** The manifest tier is authoritative and overrides the heuristics. Swept with 10% of declarations wrong, the strict false-negative rate rises to 0.097 at full coverage and the false positives stop reaching zero. A verb an integrator cannot vouch for should be left undeclared.
- **The reviewer is an oracle.** It approves on benign tasks and refuses on harmful ones by reading the benchmark's label. A real reviewer who is asked to approve 48 acts in a session is exactly the reviewer who stops reading them. The guard offers no mechanism against that, and the review load rising with coverage is a real cost, not a side note.
- **The completion rates are a direction, not an estimate.** 20 benign episodes per arm; the 0.10 and 0.30 intervals overlap (0.028–0.301 against 0.145–0.519), and the agent-loop arms use one coverage draw each, where the static curve averages over eight.
- **Coverage is sampled uniformly at random.** A real integrator declares their own surface. One who declares the destructive verbs first does better at the same coverage; one who declares only the reads does worse. The curve says nothing about which verbs to declare first beyond the obvious.

## Scope of the axis

The guard enforces irreversibility. It doesn't enforce harm, correctness or policy compliance in general. A reversible act with catastrophic content passes the guard.
