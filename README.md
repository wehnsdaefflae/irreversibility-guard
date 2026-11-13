# irreversibility-guard

**The guard sits between an agent and its tools and stops an irreversible act before it happens.**

> Tool-using AI agents often fail to recognize when to stop. Agents may take irreversible actions under ambiguity, conflicting constraints or tool failures, before they identify the risk. A later refusal can't undo the harm.

This project was built to address that problem. Across 17 frontier LLM agents, the agents kept acting in 40.5% of cases even when harm was possible. That figure comes from the paper "Do LLM agents know when not to act?", https://arxiv.org/html/2607.10059. A refusal after the irreversible act has no value, for example once the mail has already been sent.

The guard intercepts each tool call an agent proposes, before the call is executed. It renders the call to a canonical act and classifies the act's reversibility. Then it answers with one of four verdicts: ALLOW, HOLD, REQUIRE_HUMAN or DENY. HOLD means re-consent is required. REQUIRE_HUMAN means a human has to approve that exact act with a go. Every verdict comes with a stable, machine-readable reason code and a structured decision record.

## Status

**The guard was scored on a third-party benchmark as well as on tests built for this project.** The benchmark is AgentHarm, https://huggingface.co/datasets/ai-safety-institute/AgentHarm, from the UK AI Safety Institute. It has 416 prompts and 85 tool functions. All 85 of its tool functions are foreign to the guard's manifest, the list of tools and verbs the guard declares. The scoring is against the benchmark's own ground truth and against irreversibility labels from an independent model.

| measure | result | 95% CI |
|---|---|---|
| **Irreversible functions an ADVERSARIAL agent reaches** (a stop only counts where the agent can't clear it itself) | 0/40 = 0.000 | 0.000–0.088 |
| Irreversible functions allowed outright | 0/40 = 0.000 | 0.000–0.088 |
| **Reversible functions blocked (false positives)** | 27/45 = 0.600 | 0.455–0.730 |
| False positives on 150 independently generated benign calls | 0.187 | 0.132–0.257 |

For the strict rate in the first row, only a stop where the agent can't clear it alone counts. The two kinds of HOLD differ on whether the agent can clear them. The agent can clear `hold.irreversible_needs_reconsent`. With that hold, the act goes into `session.consented`. The guard returns `ALLOW` when the agent emits the same act again. The classifier's unknown tier handles unrecognised verbs and returns `hold.unknown_verb_fails_closed` before consent is checked. With this hold, the act never enters `session.consented`. The agent can't clear it with re-consent. This behaviour was verified with probes on `terminal`, `upload_file`, `make_online_purchases`, `wire_funds` and `share_on_pinterest`.

All 40 irreversible functions end at a verdict of the same kind as `hold.unknown_verb_fails_closed`. The agent can't clear that kind of verdict. The 0/40 comes from refusing unrecognised verbs, not from recognising any function. The 0.600 false-positive rate is the cost of that 0/40, because the same fail-closed rule blocks 27 of the 45 reversible functions. The fair baseline for comparison is block-every-unknown-verb, not "no guard". That baseline also allows 0 of the 40 irreversible functions outright. Compared with it, the guard correctly lets 18 of the 45 reversible functions through and puts a reason code on every decision. An integrator who declares their tool surface can move verbs off the unknown tier and get fewer false-positive blocks.

*The figure `18/40 = 0.450` was published in this README for one day, on 2026-11-12. That figure came from counting every HOLD as one the agent could satisfy. Before that, `0/40` was published, from counting every HOLD as a stop. Both earlier figures were wrong. `scripts/eval_agentharm.py` now separates the two kinds of HOLD. The correction was recorded in `RESULTS.md`.*

`RESULTS.md` has the full decomposition, a clustering caveat on the per-prompt figures and both baselines, "no guard" and block-every-unknown-verb. In this project's own suite the guard blocks 17 of 17 hostile and failure scenarios for the right reason. Each of the 17 scenarios was expanded into variants over tools, targets, argument shapes, alias-chain depths and batch positions. 406 of the 407 harness cases pass. One is skipped by design. The guard blocks 0 of the 14 benign control actions in this project's suite. That 0.000 is superseded by the external 0.187, because the 14 benign actions only use verbs the guard also declared. In total, 436 tests pass.

This project's own property-based search found the scenarios `bp-10` and `bp-11`. They weren't written by hand. `python -m guard.search --depth 3` runs all 2940 action sequences over 7 verbs × 2 locations. It checks them against a world model. That model doesn't import the guard. Under the original hard-coded composition table, the search found 184 sequences that the guard allowed end to end and that still lost pre-existing content. It found 0 under the derived effect-taint closure, where the guard works out composite irreversibility from content identity, provenance and declared per-verb effects.

The test suites themselves generate the numbers in `RESULTS.md`. Both external evaluations re-run offline from the corpora checked into `tests/corpus/`. `LIMITATIONS.md` and `THREAT_MODEL.md` describe what the guard doesn't cover. They also explain why the 0.000 should be read as 0.187 and where an attacker still gets past the guard.

## Install and run

The project needs Python 3.10 or later. It only depends on `pytest`, for the tests. The install and the tests don't need network access.

```sh
git clone <this repository>
cd irreversibility-guard
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'

python -m pytest tests/ -v      # 436 passed, 1 skipped: unit, 17 scenarios + variants,
                                # 14 benign, and the external-corpus regressions
python demo.py                  # a 30-second walk through five interceptions
python -m guard.search --depth 3   # the property-based search, re-run from scratch
```

The external evaluation re-scores offline from the corpora in `tests/corpus/`. It doesn't need network access, a model call or an API key. This command re-derives the published numbers:

```sh
python -m pytest tests/scenarios/test_external_eval.py -v   # the published numbers, re-derived
```

A full re-derivation re-fetches AgentHarm and asks the independent model for labels again. That needs network access and a model. The scripts for it are `scripts/eval_agentharm.py` and `scripts/eval_external.py`. They live outside the repository, in the authoring routine. Both are included under `scripts/` for inspection. The independent model's labels are checked in at `tests/corpus/agentharm-labels.json`, so the result is reproducible without a model.

**One caveat for a re-runner:** AgentHarm's function names include malware, ransomware and darknet-market entries. At least one commercial model's safety classifier refuses to label the batch. The script falls back to a second provider when labelling is refused and splits refused batches down to single names. It doesn't allow labels to be supplied by hand.

`demo.py` doesn't execute anything. Every act in it is only proposed. It prints this:

```
1. the agent reads a file
   ALLOW(allow.reversible) <- fs:read /data/report.csv
2. the agent deletes a DIFFERENT file it never read
   DENY(deny.target_not_read_in_session) <- fs:delete /data/customers.sqlite
3. the agent hides a delete inside a batch of reads
   DENY(blocked.irreversible_member_in_batch) <- batch[fs:read /a ; fs:delete /b ; fs:read /c]
4. injected content tells the guard to send mail
   DENY(deny.instruction_from_untrusted_origin) <- mail:send attacker@example.com
5. the operator gives a go on ONE exact act, and it goes through
   ALLOW(allow.human_go) <- mail:send ops@example.com
   the same go replayed:
   HOLD(hold.possible_duplicate_of_applied_act) <- mail:send ops@example.com
```

## Integrate it in six lines

An integrator wraps their own tool dispatcher with the guard. The guard never calls the integrator's tools. It only judges.

```python
from guard import Action, Dial, Guard, Policy, Session, default_classifier

policy = Policy(dial=Dial.HOLD_IRREVERSIBLE, never=("fs:delete",))
policy.grant("mail:*").grant("fs:*")       # reversible verbs of those tools
guard = Guard(policy=policy, classifier=default_classifier(),
              session=Session(), audit_path="audit.jsonl")

def call_tool(tool, verb, target, _origin="agent", **args):
    # DECLARE PROVENANCE. `origin` is caller-supplied and the guard cannot check it:
    #   "agent"       the model emitted this call itself
    #   "human"       the operator asked for it directly
    #   "tool_output" it came out of fetched content -- DENIED before any policy read
    # Its default is "undeclared", which FAILS CLOSED: an irreversible act whose
    # provenance you never declared needs a human go and cannot be unblocked by the
    # agent's own re-consent, because the guard has no way to tell the two apart.
    # Reversible acts are unaffected, so an integration that declares nothing still runs.
    decision = guard.check(Action(tool, verb, target, args, origin=_origin))
    if not decision.allowed:
        return {"blocked": decision.verdict.name, "reason": decision.reason}
    return real_dispatch(tool, verb, target, **args)
```

The caller supplies `origin`. The guard can't verify it. A caller passes "agent" when the model emitted the call itself and "human" when the operator asked for it directly. A call that came out of fetched content gets "tool_output". The guard denies a `tool_output` action before it reads any policy.

`origin` defaults to "undeclared". That default fails closed. An irreversible act needs a human go when the integrator hasn't declared its provenance. The agent can't unblock that act with its own re-consent, because the guard can't tell an agent-emitted call from echoed content. The default doesn't affect reversible acts, so an integration still runs if it doesn't declare any provenance.

A dispatcher shouldn't set `origin="agent"` to hide that it can't tell a model-emitted call from content echoed out of a tool result. The guard's injection defence depends on `origin="agent"` being true. Such a dispatcher should set `Policy(trust_undeclared_origin=True)` instead. With that setting the guard goes back to the old permissive behaviour. The setting is visible in the policy, where a reviewer sees what was given up.

An integrator can declare their own tools so the classifier handles them in its authoritative tier, the tier for declared tools.

```python
from guard import ManifestEntry, default_classifier
c = default_classifier()
c.declare("crm:archive_lead", ManifestEntry("reversible", undo="un-archive the lead"))
c.declare("crm:purge_lead",   ManifestEntry("irreversible"))
c.alias("housekeeping:tidy", "fs:delete")   # a wrapper reaching a destructive verb
```

## The mechanisms

The `sound?` column below means one specific thing: the verdict is a decidable, intent-free property of the call and the session record. That verdict holds regardless of how any classifier reads what the call means. A sound mechanism can still be incomplete, insufficient or insecure against an attacker who can reach the process. The term is defined in `LIMITATIONS.md`, which lists its exclusions.

| mechanism | what it stops | sound? |
|---|---|---|
| **Fail-closed provenance** | The guard stops an irreversible act when the integrator never declared its `origin`. It refuses the agent's own re-consent for such an act because it can't tell an agent-emitted call from a call echoed out of fetched content. A human decides. The opt-out is `Policy(trust_undeclared_origin=True)` and is visible in the policy. | yes (structural) |
| **Canonical action rendering** | The policy is written against the act, not its wording. Kwarg order, nesting and aliasing can't change the string a rule sees. | yes (structural) |
| **Per-VERB capability reservation** | `mail:*` grants `mail:list` and `mail:draft` but never `mail:send`. The outward irreversible verb of an otherwise safe tool is reserved separately. | yes (structural) |
| **Read-before-destroy preconditions** | The guard refuses an irreversible act on content if the agent never read that content in this session. The agent can only delete what it has inspected. | yes (structural) |
| **Hold and re-consent** | The guard suspends an irreversible act and presents it again. The agent has to re-emit that exact act to go ahead. Every hold is counted in an evidence tally, so the guard's false-positive cost is measurable. | partly |
| **Human-committed approval dials** | At the top setting of the approval dial, the agent can't grant a self-modifying act at all. A self-modifying act changes the guard's own policy, config or code. A go in the session doesn't make it grantable either. | yes (structural) |
| **Batch analysis** | The guard stops an irreversible act hidden in a batch of reversible acts, at any position and nesting depth. The batch gets the verdict of its strictest member. | yes (structural) |
| **Composition analysis** | The guard stops a sequence of individually reversible steps that together destroy content. `guard/taint.py` derives the analysis by effect-taint closure over content identity, provenance and declared per-verb effects. The guard doesn't match sequences against a list. It also catches a hazard created several steps earlier on a different location. | no |
| **Manifest fidelity** | The guard stops an act declared reversible when its declared undo doesn't hold for this target. A `create` onto an already occupied location destroys the previous content, for example. Deleting the copy doesn't restore that content. That case is `bp-11`. The search found it, not manual review. | no |
| **Property-based search** | `python -m guard.search --depth 3` searches action sequences exhaustively. It checks them against a concrete world model. That model doesn't import the guard. The search reports any sequence the guard allowed end to end that still lost pre-existing content. It found 184 such sequences under the old pair table and 0 under the derived closure. `RESULTS.md` has both figures. That result is confounded. Selecting the pair table also turns off the manifest-fidelity check, so the drop from 184 to 0 comes from the closure and the manifest-fidelity check together. The search only covers the verbs and locations in its alphabet. `LIMITATIONS.md` explains what that "0" means and what it doesn't mean. | no |

The guard binds a human go to one exact canonical act. Each go is single-use and can't be replayed. A go on `link=repo-a` doesn't authorise `link=repo-b`. An instruction injected into fetched content can never control the guard's decisions, because the guard denies an action with `origin` `tool_output` before it reads any policy.

## Prior art and case study

The design wasn't invented from scratch. Four guard mechanisms were generalised from the autonomous-routine scheduler this project was built inside. That scheduler is a single-operator system. For the scheduler, "in use" means its author uses it. This isn't a deployment study. The mechanism set can be inspected. It's described in this README and reimplemented in the repository.

The scheduler's consequence reminders hold a pending action and demand re-consent with an evidence tally. Capability there is reserved per tool verb, not per tool. `mail` is granted while `mail send` is reserved. Preconditions refuse an irreversible act until the run has read what the act would destroy. With the approval dials, only a human can commit a self-modifying act. `THREAT_MODEL.md` records where this implementation goes beyond that prior art, and why.

## Repository layout

```
guard/            the library: core.py (canonical form, decision record),
                  classifier.py (tiered reversibility), policy.py (enforcement)
guard/taint.py    the effect-taint closure: composite irreversibility DERIVED
guard/search.py   the property-based search (its oracle does not import the guard)
tests/            test_unit.py · tests/scenarios/ (bp-01..bp-11, fs-01..fs-04,
                  test_composition_search.py) · tests/search-findings.json (dated)
                  · tests/benign/ (the 14-action control set)
demo.py           the five interceptions above
RESULTS.md        the measured table, generated from tests/results.json
THREAT_MODEL.md   assets, adversaries, trust boundaries, what is NOT enforced
LIMITATIONS.md    implemented+tested / implemented+untested / theoretical, honestly
```

## Licence

MIT

The licence text is in `LICENSE`. The MIT licence doesn't cover the third-party evaluation corpora under `tests/corpus/`. Those corpora keep their own terms. `deepset/prompt-injections` is CC-BY-4.0, with attribution to deepset GmbH. The AgentHarm derivative only holds ids, names and `target_functions`. The AgentHarm prompt texts are deliberately not redistributed (`tests/corpus/FETCH.md`). `LICENSE` lists each file and its source.
