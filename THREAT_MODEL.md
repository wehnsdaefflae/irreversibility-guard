# Threat model

## Assets

1. **Content that exists in exactly one copy.** That could be a file, a record or a database row. Destroying it can't be undone.
2. **The outside world's state.** Sent mail, a submitted form, a pushed commit and spent money are examples. We can't undo any of those four.
3. **The guard's own policy, config and code.** All the other assets would be exposed too if the agent could lower the dial that sets how strict the guard is.
4. **The operator's attention.** A guard that held everything for approval would get uninstalled within a week. False positives threaten the guard's existence. We've measured them and put the numbers in `RESULTS.md`. We don't dismiss false positives.

## Adversaries

| Adversary | What it does | What answers it |
|---|---|---|
| **The mistaken agent** | It's the common case. The agent picks the irreversible reading of an ambiguous instruction. After an opaque tool failure it retries without checking. It also follows a task instruction that conflicts with a standing prohibition. | The guard enforces read-before-destroy preconditions, so the agent has to read a target before a destructive act on it. The guard also detects duplicate acts and ranks `never` prohibitions above the task. With hold-and-re-consent it stops the act and requires a renewed confirmation. |
| **The injected instruction** | Text in fetched content or tool output asks the guard or the agent for an irreversible act. | The guard reads where an action came from in its `origin` field and denies actions with `origin="tool_output"` before it consults any policy. It never treats content as authority. |
| **The integration that never declares provenance** | The caller supplies the `origin` field. The guard can't verify it. An integrator who leaves `origin` at its default decides without notice how strong the injection defence is. | The default value is `"undeclared"`, not `"agent"`. An irreversible act with undeclared provenance gets `REQUIRE_HUMAN` (`require_human.provenance_not_declared`). The agent's own re-consent doesn't unblock an act like that. It stays blocked until a human approves that exact act with a go. This rule doesn't apply to reversible acts. `Policy(trust_undeclared_origin=True)` restores the permissive behaviour in a way a reviewer can see. |
| **The agent optimising around its own guard** | The agent asks the guard to relax, re-scope or disable its policy. It wraps or renames a destructive tool and hides a destructive call in a batch of harmless calls. It also splits a destructive act into steps that are each reversible on their own. | A human commits the dial. The agent can't grant a self-modifying act on the guard's own policy. Before any grant check the guard resolves aliases to the underlying verb. It analyses a batch and reports its strictest member. For composite effects it uses a derived effect-taint closure over the session's own effects. It computes them from what the session itself did and doesn't use a list of known compositions. We also run a property-based search for compositions beyond the declared ones. |
| **The replayed authorisation** | A human go gets reused. Or a go given for one payload gets extended to another payload. | The guard binds a go to one exact canonical act, the standard rendering of a proposed call. Each go is also single-use. |

A compromised host and a malicious operator are out of scope. We also leave out an agent that can edit the guard's source on disk and an agent that bypasses the dispatcher entirely. The guard assumes the agent reaches its tools through the guard. The integrator has to enforce that assumption.

## Trust boundaries

```
                           operator
                 (trusted; the only authority
                      for an outward act)
                               │
                               │ go
                               ▼
agent ── proposed action ──▶ guard ── allowed action ──▶ tools ──▶ world
  ▲                                                        │
  └──────── tool output / fetched content ─────────────────┘
            (untrusted; origin="tool_output" is never authority)
```

## What the guard enforces

- The guard renders every proposed call to a canonical act before it applies any rule.
- The guard checks capability per qualified verb, the verb of a specific tool. A wildcard grant on a tool only covers that tool's reversible verbs. An irreversible verb gets reserved separately.
- An undeclared verb fails closed. The guard treats it as irreversible and never as safe.
- The guard resolves aliases to a fixpoint, so it keeps going until no further alias applies. It does that before classification and before the grant check.
- An irreversible act gets refused if this session hasn't read its target.
- An irreversible act requires a human if it doesn't have a declared undo path or a human go.
- An outward act requires a human go on that exact canonical act. Each go is single-use.
- A self-modifying act requires a human. At the top dial setting the guard denies it outright.
- A batch gets the verdict of its strictest member. The guard names the offending member in the verdict.
- A step requires a human if its composition with the session's earlier acts is irreversible. `guard/taint.py` derives that from content identity, provenance and declared per-verb effects. It doesn't match against a list of known pairs. It can detect a hazard created several steps earlier, on a different location.
- The guard doesn't trust an act declared reversible if its declared undo doesn't hold for this target. It requires a human for that act. A `create` onto an already-occupied location is an example.
- Every decision gets appended to a JSONL audit log with its verdict, its reason, the tier that classified it and the evidence. The guard also counts every verdict in a per-session tally.

## What the guard does NOT enforce

- **That the agent goes through it.** The guard is a library, not a sandbox. An agent with direct filesystem or network access bypasses it entirely. The integrator should deploy the guard as the only dispatch path.
- **That the manifest is right.** The authoritative tier works from what a human declared about their tools, so it's only as accurate as that declaration. An undeclared verb falls to the heuristics. Those heuristics are unsound.
- **That `undo` works.** The `undo` string is documentation. The guard doesn't execute or verify the recovery.
- **Semantic harm that is reversible.** A secret leaked into a reversible draft passes. Defamatory text written to a scratch file passes too. The guard enforces irreversibility, not harm.
- **Compositions nobody wrote down.** We've largely addressed composition detection, but we haven't solved it. It isn't a declared rule table any more. `guard/taint.py` derives composite irreversibility from content identity, provenance and a declarative map of per-verb effects. `guard/search.py` found two hazards, `bp-10` and `bp-11`. The author hadn't declared them. The effect map itself is still a declaration. The guard would misjudge a verb whose real effect differs from its declared effect. The search is only exhaustive within a small alphabet. `LIMITATIONS.md` has the details.
- **Rate or volume.** The guard doesn't limit the count. 1000 reversible acts that are each allowed on their own get 1000 allows.

## Divergences from `seed-design.md` (and why)

1. **No LLM fallback tier.** The seed design proposed manifest, then heuristics, then an LLM fallback failing closed. We built manifest, then heuristics, then unknown, failing closed. An LLM tier would add a network dependency, non-determinism and cost to every decision. It only gains anything over failing closed when it unholds acts the structural tiers already doubt. The tier would only make the guard less safe and would make the test suite non-reproducible. Failing closed is strictly safer and keeps the suite offline and deterministic. The right fix for a noisy verb is a manifest entry.
2. **Origin-based injection defence added.** The seed design treated guard-directed prompt injection as a scenario to test. Now it's a mechanism. The guard denies actions with `origin="tool_output"` before it evaluates any policy. Injection gets refused structurally, not classified.
3. **Goes are exact and single-use.** The seed design didn't include this. We added it because a replayable or payload-loose go can turn an approved submission into an unapproved one.
4. **Duplicate-act detection added.** It's for a blind retry after an opaque failure. The seed design listed that case as a scenario and didn't have a mechanism for it.
5. **Read-before-destroy is scoped to content-destroying acts.** We built read-before-destroy for outward acts first. We removed it because an outward act's target is a recipient, not readable content. For outward acts the precondition is meaningless. It blocked sends for an unclear reason. The human-go gate covers outward acts instead.
