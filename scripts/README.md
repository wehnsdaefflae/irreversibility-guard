# Evaluation scripts (for inspection and re-derivation)

These two scripts produced the external evaluation reported in `../RESULTS.md`. They are
included so the protocol can be audited, not because they are needed to reproduce the
numbers: the corpora and the independent model's labels are checked into `../tests/corpus/`,
and `python -m pytest tests/scenarios/test_external_eval.py` re-derives the verdicts
offline with no network and no model call.

- `eval_agentharm.py` — fetches AgentHarm, has an INDEPENDENT model (shown no guard
  source, no manifest and no mention of a guard) label each of the 85 tool functions
  destructive/outward, then scores the guard per call and per prompt with Wilson 95%
  intervals against a no-guard baseline.
- `eval_external.py` — the same for `deepset/prompt-injections` (reported as a negative
  result: it is a text-classification corpus and maps to almost no tool calls) and for the
  150 independently generated benign agent calls.

They were written as helper scripts of the authoring automation, so they shell out to that
instance's model utilities (`gu claude`, `gu llm-complete`). Re-deriving from scratch means
substituting your own model call in `ask_model`; everything downstream of that is plain
standard-library Python.

Paths inside them resolve relative to a repository checkout as well: both resolve the
project root by walking up from the script, so `python scripts/eval_agentharm.py score`
works from the repository root once `artifacts/` and the repo root coincide — in the
published repository they do.
