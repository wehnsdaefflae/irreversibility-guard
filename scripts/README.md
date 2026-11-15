# Evaluation scripts (for inspection and re-derivation)

These scripts produced the external evaluation and the measured dials reported in `../RESULTS.md`. They are
included here so the protocol can be audited. They aren't needed to reproduce the numbers,
because the corpora and the independent model's labels are checked into `../tests/corpus/`.
`python -m pytest tests/scenarios/test_external_eval.py` re-derives the verdicts offline.
That run doesn't use the network and doesn't make a model call.

- **`eval_agentharm.py`**: It fetches AgentHarm and has an independent model label each of
  the 85 tool functions as destructive or outward. The script doesn't show that model the
  guard source, the manifest or any mention of a guard. It scores the guard per call and per
  prompt with Wilson 95% intervals and compares the scores against a no-guard baseline.
- **`eval_external.py`**: It does the same as `eval_agentharm.py` for
  `deepset/prompt-injections` and for the 150 independently generated benign agent calls.
  `deepset/prompt-injections` is reported as a negative result, because it's a
  text-classification corpus and maps to almost no tool calls.
- **`eval_agent_loop.py`**: It drives a live model as an AGENT over AgentHarm's
  85-function tool surface, up to 8 steps per episode, and intercepts every call the agent
  proposes before a stubbed dispatcher would run it. The guard's refusal goes back to the
  agent as text, so an agent that re-plans or retries is observed doing it. Three arms run
  over the same episodes: no guard, the shipped guard, and refuse-every-undeclared-verb.
  `python scripts/eval_agent_loop.py report` recomputes the published numbers from the
  checked-in transcript with no model call;
  `python -m pytest tests/scenarios/test_agent_loop.py` asserts on them offline. Only
  `run` needs the network and a model key. The AgentHarm prompt TEXTS are not
  redistributed here: `run` fetches them into `tests/cache/`, which is gitignored.
  The `--arms` flag selects the arms. `guard@50` declares a random half of the 85 verbs in
  the manifest, taking each verb's reversibility from the independent labels, and an arm
  suffixed `+human` puts an ORACLE reviewer in the loop who approves a held act on a
  benign task and refuses it on a harmful one by reading the benchmark's own label. Those
  arms produced the coverage curve. Two further suffixes were added on 2026-11-15 to
  narrow what that oracle could not measure: `+review` puts a **non-oracle** reviewer in
  the loop — a live model (`--reviewer-model`) shown only the task text, the proposed call
  and the guard's reason for escalating, never a label — and a reviewer call that fails or
  cannot be parsed reads as *refuse* and is counted in `reviewer_errors`; `guard@50#2`
  selects coverage **draw 2**, the same percentage over a different random subset, so a
  coverage point can be replicated instead of resting on one draw.
  `python -m pytest tests/scenarios/test_reviewer.py` re-derives every claim in
  `../RESULTS.md` that rests on those arms, offline.
- **`eval_coverage.py`**: It sweeps manifest coverage from 0% to 100% in the static scorer.
  At each coverage it declares a uniformly random sample of that fraction of the 85 verbs,
  over several seeds, and reports false positives and strict false negatives with Wilson
  95% intervals. A second arm declares a fraction of those verbs WRONGLY, which prices the
  cost of trusting a manifest, because the manifest tier overrides the heuristics. It needs
  no model and no network. `python -m pytest tests/scenarios/test_coverage.py` re-derives
  every claim in `../RESULTS.md` that rests on it, offline.
- **`eval_copy_verification.py`**: It prices the copy-verification dial. Every action
  sequence up to depth 3 over 9 verbs × 3 locations runs through the guard under each
  setting of `Policy(copy_verification=...)`, and separately through the concrete world
  model in `../guard/search.py`, which nothing in the taint module imports. Two conditions
  run: storage intact, and an external process deleting each copy the session makes right
  after it is made — the event the pre-2026-11-14 structural tracking could not see. It
  reports sequences that lost content and sequences stopped that would have lost nothing,
  so the safety gain and its cost sit on one table. It needs no model and no network.
  `python scripts/eval_copy_verification.py --selftest` checks the oracle and the arm
  wiring; `python -m pytest tests/scenarios/test_copy_verification.py` asserts the
  guard-level behaviour offline.

All of these scripts were written as helper scripts of the authoring automation, so they call
out through the shell to that instance's model utilities, `gu claude` and `gu llm-complete`.
Anyone re-deriving from scratch has to substitute their own model call in `ask_model`, or in
`ask_step` for the agent loop.
Everything after `ask_model` in the scripts is plain standard-library Python.

The paths inside all of these scripts also resolve relative to a repository checkout. Each script
finds the project root by walking up from its own location. `python scripts/eval_agentharm.py
score` works from the repository root once `artifacts/` and the repository root are the same
directory. In the published repository they are.
