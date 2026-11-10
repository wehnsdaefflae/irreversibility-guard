# Threat model

## Assets

1. **Content that exists in exactly one copy** — a file, a record, a database row whose
   destruction cannot be undone.
2. **The outside world's state** — a mail that has been sent, a form that has been
   submitted, a commit that has been pushed, money that has been spent. There is no undo.
3. **The guard's own policy, config and code.** If the agent can lower the dial, every
   other asset follows.
4. **The operator's attention.** A guard that holds everything is uninstalled within a
   week, so false positives are a threat to the guard's existence and are measured
   (`RESULTS.md`), not waved away.

## Adversaries

| adversary | what it does | what answers it |
|---|---|---|
| **The mistaken agent** (the common case) | resolves an ambiguous instruction to its irreversible reading; retries blindly after an opaque tool failure; obeys a task instruction that contradicts a standing prohibition | read-before-destroy preconditions, duplicate-act detection, `never` prohibitions outranking the task, hold-and-re-consent |
| **The injected instruction** | text in fetched content or tool output that addresses the guard or the agent and asks for an irreversible act | actions carrying `origin="tool_output"` are denied **before any policy is consulted**; the guard never treats content as authority |
| **The agent optimising around its own guard** | asks the guard to relax, re-scope or disable its policy; wraps or renames a destructive tool; hides one destructive call in a batch of harmless ones; splits a destructive act into individually-reversible steps | human-committed dial (self-modifying acts not agent-grantable), alias resolution to the underlying verb before any grant check, batch analysis surfacing the strictest member, composition rules |
| **The replayed authorisation** | reuses a human go, or stretches a go given for one payload to cover another | a go binds to one exact canonical act and is single-use |

**Explicitly out of scope:** a compromised host, a malicious *operator*, an agent that
can edit the guard's source on disk or bypass the dispatcher entirely. This guard assumes
the agent reaches its tools *through* it. Enforcing that assumption is the integrator's
job (see "What the guard does not enforce").

## Trust boundaries

```
   operator ──go──┐                      (trusted: the only authority for an outward act)
                  v
 agent ──proposed action──> [ GUARD ] ──allowed action──> tools ──> world
          ^                                                  |
          └──── tool output / fetched content ───────────────┘
                 (UNTRUSTED: origin="tool_output" is never authority)
```

## What the guard enforces

- Every proposed call is rendered to a canonical act before any rule sees it.
- Capability is checked **per qualified verb**. A wildcard grant on a tool covers its
  reversible verbs only; the irreversible verb is separately reserved.
- An undeclared verb **fails closed** — treated as irreversible, never as safe.
- Aliases are resolved to a fixpoint before classification *and* before the grant check.
- An irreversible act on a target not read in this session is refused.
- An irreversible act with no declared undo path and no human go requires a human.
- An outward act requires a human go on that exact canonical act; the go is single-use.
- A self-modifying act requires a human, and at the top dial is denied outright.
- A batch inherits its strictest member's verdict, naming the offending member.
- A step completing a known irreversible composition requires a human.
- Every decision is appended to a JSONL audit log with its verdict, reason, tier and
  evidence, and every verdict is counted in a per-session tally.

## What the guard does NOT enforce

- **That the agent goes through it.** The guard is a library, not a sandbox. An agent
  with direct filesystem or network access bypasses it entirely. Deploy it as the only
  dispatch path.
- **That the manifest is right.** The authoritative tier is only as good as what a human
  declared about their tools. An undeclared verb falls to heuristics, which are unsound.
- **That `undo` works.** An `undo` string is documentation; the guard does not execute or
  verify recovery.
- **Semantic harm that is reversible.** Leaking a secret into a reversible draft, or
  writing something defamatory to a scratch file, passes: the axis enforced is
  *irreversibility*, not *harm*.
- **Compositions nobody wrote down.** Composition detection is a declared rule table,
  not an inference engine; see `LIMITATIONS.md`.
- **Rate or volume.** A thousand individually-allowed reversible acts are a thousand
  allows.

## Divergences from `seed-design.md` (and why)

1. **No LLM fallback tier.** The seed design proposed manifest → heuristics → *LLM
   fallback that fails closed*. Built instead: manifest → heuristics → **unknown, failing
   closed**. An LLM tier would add a network dependency, non-determinism and cost to
   every decision, while its only improvement over failing closed is *unholding* acts the
   structural tiers already doubt — i.e. it can only make the guard less safe, and makes
   the test suite non-reproducible. Failing closed is strictly safer and keeps the suite
   offline and deterministic. A manifest entry is the right fix for a noisy verb.
2. **Origin-based injection defence added.** The seed design treated guard-directed prompt
   injection as a scenario to test. It became a *mechanism*: `origin="tool_output"` is
   denied before policy evaluation, so injection is refused structurally rather than
   classified.
3. **Goes are exact and single-use.** Not in the seed design; added because a go that is
   replayable or payload-loose is how an approved submission becomes an unapproved one.
4. **Duplicate-act detection added** for the blind-retry-after-opaque-failure case, which
   the seed design listed as a scenario with no mechanism behind it.
5. **Read-before-destroy is scoped to content-destroying acts.** Applying it to outward
   acts was built first and removed: an outward act's target is a recipient, not readable
   content, so the precondition was meaningless there and blocked sends for an
   unintelligible reason. The human-go gate covers outward acts instead.
