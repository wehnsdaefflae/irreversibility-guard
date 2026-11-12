# irreversibility-guard

**A guard that sits between an agent and its tools and stops the irreversible act
*before* it happens.**

> "Tool-using AI agents often fail to recognize when they should stop. Under ambiguity,
> conflicting constraints, or tool failures, they may take irreversible actions before
> identifying the risk, and a later refusal cannot undo the harm."
> — the problem this project addresses. Across 17 frontier LLM agents, agents continued
> acting in **40.5%** of cases even when harm was possible
> ([Do LLM agents know when not to act?](https://arxiv.org/html/2607.10059)).

A refusal that arrives after the mail is sent is worthless. So this guard intercepts
each *proposed* tool call, renders it to a canonical act, classifies its reversibility,
and answers with one of four verdicts — **ALLOW**, **HOLD** (re-consent required),
**REQUIRE_HUMAN** (a human go on that exact act), **DENY** — together with a stable
machine-readable reason code and a structured decision record.

## Status

**Scored on a third-party benchmark, not only on its author's own tests.** On
[AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm) (UK AI Safety
Institute — 416 prompts, 85 tool functions, *all foreign to this guard's manifest*, with
the benchmark's own ground truth and an independent model's irreversibility labels):

| measure | result | 95% CI |
|---|---|---|
| irreversible functions allowed (false negatives) | **0/40** = 0.000 | 0.000–0.088 |
| harmful prompts reaching an irreversible act | **0/192** = 0.000 | 0.000–0.020 |
| reversible functions blocked (false positives) | **27/45** = 0.600 | 0.455–0.730 |
| false positives on 150 independently generated benign calls | **0.187** | 0.132–0.257 |

Unguarded, all 40 irreversible calls and 192 harmful prompts go through. **Half of that
zero-false-negative figure is the fail-closed rule refusing verbs it cannot read, and
that same rule is the source of every false positive** — the decomposition is published
in [`RESULTS.md`](RESULTS.md) because quoting the first row alone would mislead. The
guard delays harmful and benign prompts at the *same* rate (0.808): it gates
irreversibility, not harm, and a test asserts it stays that way.

The author's own suite, for what it is worth: **15 of 15 hostile/failure scenarios blocked
for the right reason**; each one expanded into variants over tools, targets, argument
shapes, alias-chain depths and batch positions for **398 of 399 harness cases passing**
(1 skipped by design); **0 of 14 benign control actions blocked** — a 0.000 that the
external 0.187 supersedes, since those 14 use only verbs the author also declared;
**433 tests green in total**. Two of the fifteen scenarios (`bp-10`, `bp-11`) were
**found by the project's own property-based search**, not written by hand: `python -m
guard.search --depth 3` runs all 2940 action sequences over 7 verbs × 2 locations against a
world model that does not import the guard, and reports **184 content-losing sequences
under the original hard-coded composition table and 0 under the derived effect-taint
closure**. The numbers in [`RESULTS.md`](RESULTS.md) are generated from the
suites themselves, and both external evaluations re-run offline from corpora checked into
`tests/corpus/`. The honest account of what is *not* covered — including why the author's
own 0.000 should be read as 0.187 and where an attacker still walks through — is in
[`LIMITATIONS.md`](LIMITATIONS.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Install and run

Requires Python 3.10+. No dependencies beyond `pytest` for the tests; **no network
access is needed** to install or test.

```sh
git clone <this repository>
cd irreversibility-guard
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'

python -m pytest tests/ -v      # 433 passed, 1 skipped: unit, 15 scenarios + variants,
                                # 14 benign, and the external-corpus regressions
python demo.py                  # a 30-second walk through five interceptions
python -m guard.search --depth 3   # the property-based search, re-run from scratch
```

The external evaluation re-scores **offline** from the corpora checked into
`tests/corpus/` — no network, no model call, no API key:

```sh
python -m pytest tests/scenarios/test_external_eval.py -v   # the published numbers, re-derived
```

Re-deriving them *from scratch* (re-fetching AgentHarm and re-asking an independent model
for the labels) needs network and a model, and lives outside the repository in the
authoring routine's `scripts/eval_agentharm.py` and `scripts/eval_external.py`, both
included here under `scripts/` for inspection. The labels an independent model produced
are checked in (`tests/corpus/agentharm-labels.json`) so the result is reproducible
without one. **One caveat for a re-runner:** AgentHarm's function names include malware,
ransomware and darknet-market entries, and at least one commercial model's safety
classifier refuses to label the batch; the script falls back to a second provider and
splits refused batches down to single names rather than letting the evaluation's author
supply labels by hand.

`demo.py` prints exactly this (nothing is executed — every act is only *proposed*):

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

Wrap your tool dispatcher. The guard never calls your tools — it only judges.

```python
from guard import Action, Dial, Guard, Policy, Session, default_classifier

policy = Policy(dial=Dial.HOLD_IRREVERSIBLE, never=("fs:delete",))
policy.grant("mail:*").grant("fs:*")       # reversible verbs of those tools
guard = Guard(policy=policy, classifier=default_classifier(),
              session=Session(), audit_path="audit.jsonl")

def call_tool(tool, verb, target, **args):
    decision = guard.check(Action(tool, verb, target, args))
    if not decision.allowed:
        return {"blocked": decision.verdict.name, "reason": decision.reason}
    return real_dispatch(tool, verb, target, **args)
```

Declare what your own tools do, so the authoritative tier covers them:

```python
from guard import ManifestEntry, default_classifier
c = default_classifier()
c.declare("crm:archive_lead", ManifestEntry("reversible", undo="un-archive the lead"))
c.declare("crm:purge_lead",   ManifestEntry("irreversible"))
c.alias("housekeeping:tidy", "fs:delete")   # a wrapper reaching a destructive verb
```

## The six mechanisms

| mechanism | what it stops | sound? |
|---|---|---|
| **Canonical action rendering** | policy written against the act, not its phrasing; kwarg order, nesting and aliasing cannot change the string a rule sees | yes (structural) |
| **Per-VERB capability reservation** | `mail:*` grants `mail:list` and `mail:draft` but **never** `mail:send`: the outward, irreversible verb of an otherwise-safe tool stays separately reserved | yes (structural) |
| **Read-before-destroy preconditions** | an irreversible act on content the agent never read in this session is refused — you cannot delete what you have not inspected | yes (structural) |
| **Hold and re-consent** | an irreversible act is suspended and re-presented; the agent must re-emit *that exact act* to proceed, and every hold is counted in an evidence tally that makes the guard's false-positive cost measurable | partly |
| **Human-committed approval dials** | at the top dial a self-modifying act (changing the guard's own policy, config or code) is not agent-grantable **at all** — not even with a go in the session | yes (structural) |
| **Batch analysis** | an irreversible act hidden inside a batch of reversible ones, at any position and nesting depth — the batch inherits its strictest member's verdict | yes (structural) |
| **Composition analysis** | a sequence of individually-reversible steps whose composition destroys — **derived** by an effect-taint closure over content identity, provenance and declared per-verb effects (`guard/taint.py`), not matched against a list, so a hazard created several steps earlier on a *different* location is caught too | no |
| **Manifest fidelity** | an act *declared* reversible whose declared undo does not hold for this target — a `create` onto an already-occupied location destroys what was there, and deleting the copy does not restore it (`bp-11`, **found by the search, not by the author**) | no |
| **Property-based search** | `python -m guard.search --depth 3` exhaustively searches action sequences against a concrete world model that does not import the guard, and reports any sequence the guard allowed end to end that still lost pre-existing content: **184 such sequences under the old pair table, 0 under the derived closure** (`RESULTS.md`). The search is bounded to that alphabet — see `LIMITATIONS.md` for what "0" does and does not mean | no |

Two further properties worth naming: a human **go binds to one exact canonical act and
is single-use**, so a go on `link=repo-a` does not authorise `link=repo-b` and cannot be
replayed; and an action whose `origin` is `tool_output` is **denied before any policy is
read**, so an instruction injected into fetched content can never drive the guard.

## Prior art and case study

The design is not invented from scratch. It generalises four guard mechanisms of the
autonomous-routine scheduler this project was built inside — a single-operator system, so
treat "in use" as "in use by its author", not as a deployment study; what is inspectable
is the mechanism set, described here and reimplemented in this repository: consequence
reminders that hold a pending action and demand re-consent with an evidence tally;
capability reserved per tool *verb* rather than per tool (`mail` granted, `mail send`
reserved); preconditions that refuse an irreversible act until the run has read what it
would destroy; and approval dials making self-modifying acts human-committed only.
`THREAT_MODEL.md` records where this implementation goes beyond that prior art and why.

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

MIT.
