# What is in this directory, and what is deliberately NOT

The external evaluation results are in `../../RESULTS.md`. That evaluation is scored on
third-party corpora. This directory only holds the files needed to re-derive the published
numbers.

| File | What it is |
| --- | --- |
| `agentharm-index.jsonl` | It has 416 rows, one for each AgentHarm prompt. A row holds the prompt's id, name, config and split. It also holds `target_functions`, the tool calls the benchmark says that prompt is meant to drive. |
| `agentharm-labels.json` | It holds a `destructive` label and an `outward` label for each of 85 functions. A model produced the labels. That model was shown no guard source, no manifest and no mention of a guard. |
| `benign-traffic.jsonl` | An independent model generated these 150 legitimate agent calls over a real tool surface. |
| `prompt-injections.jsonl` | It's `deepset/prompt-injections` under CC-BY-4.0, 662 rows. It stays in this directory because it's reported as a negative result. |
| `translated.jsonl` | An independent model mapped the `deepset/prompt-injections` corpus to proposed tool calls. |

The AgentHarm prompt texts are deliberately not redistributed here. There are 208 of those
prompts. They were written to push an agent into harmful tool use. This repository doesn't
need the texts, because the evaluation uses `target_functions`, not the prompt text.
Republishing a harm corpus is outside this project's role. Readers can get the prompt texts
from the source.

```sh
# The source dataset is ai-safety-institute/AgentHarm.
# Its configs are harmful and harmless_benign.
# Its splits are test_public and validation.
curl -s "https://datasets-server.huggingface.co/rows?dataset=ai-safety-institute%2FAgentHarm&config=harmful&split=test_public&offset=0&length=100"
# This fetches config harmful, split test_public, at offset 0 with length 100.
```

The published numbers don't depend on having the AgentHarm prompt texts. The ids in this
directory match the AgentHarm benchmark's own ids, so any claim in `RESULTS.md` can be
checked against the source.
