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

Measured, not asserted: **13 of 13 hostile/failure scenarios blocked for the right
reason**; each one additionally expanded into variants over tools, targets, argument
shapes, alias-chain depths and batch positions for **387 of 388 harness cases passing**
(1 skipped by design); **0 of 14 benign control actions blocked — false-positive rate
0.000**; 29 unit tests. The numbers in [`RESULTS.md`](RESULTS.md) are generated from the
suites themselves. The honest account of what is *not* covered — including why a
14-action control set is weak evidence and where an attacker still walks through — is in
[`LIMITATIONS.md`](LIMITATIONS.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Install and run

Requires Python 3.10+. No dependencies beyond `pytest` for the tests; **no network
access is needed** to install or test.

```sh
git clone <this repository>
cd irreversibility-guard
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'

python -m pytest tests/ -v      # 416 cases: 29 unit, 13 scenarios + their variants, 14 benign
python demo.py                  # a 30-second walk through five interceptions
```

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
| **Composition analysis** | a sequence of individually-reversible steps whose composition destroys (append→truncate, write→delete) — **against a declared table of four compositions, not by inference**: a composition nobody wrote down is not caught (see `LIMITATIONS.md`) | no |

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
tests/            test_unit.py · tests/scenarios/ (bp-01..bp-08, fs-01..fs-04)
                  · tests/benign/ (the 14-action control set)
demo.py           the five interceptions above
RESULTS.md        the measured table, generated from tests/results.json
THREAT_MODEL.md   assets, adversaries, trust boundaries, what is NOT enforced
LIMITATIONS.md    implemented+tested / implemented+untested / theoretical, honestly
```

## Licence

MIT.
