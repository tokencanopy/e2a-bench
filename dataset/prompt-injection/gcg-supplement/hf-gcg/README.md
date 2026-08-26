# HuggingFace Real GCG Supplement

This directory contains a reproducible sampled subset of real GCG suffixes from
`MatanBT/gcg-evaluated-data`.

- Source: https://huggingface.co/datasets/MatanBT/gcg-evaluated-data
- License: MIT
- Upstream format: Parquet / HuggingFace dataset
- Local use: real mixed alpha/symbol GCG suffix challenge for email detectors

## Files

- `fetch_hf_gcg.py` downloads a deterministic evaluated-row subset into
  `seeds.jsonl`.
- `render_hf_gcg.py` renders `seeds.jsonl` into plaintext EML files and
  `manifest.jsonl`.
- `eml/` and `manifest.jsonl` are generated artifacts committed for
  reproducible eval runs.

The original harmful prompts are not used as email bodies. Each suffix is
attached to a synthetic innocuous business email body so this slice measures
whether a detector catches the adversarial suffix itself.

The upstream dataset evaluates a smaller set of optimized suffixes across many
messages. The default local subset therefore contains 10,000 evaluated rows with
`strongreject_finetuned >= 0.5`, not 10,000 independent unique suffix strings.
Pass `--dedupe-suffix` to `fetch_hf_gcg.py` when a unique-suffix-only challenge
set is needed.

## Regenerate

```bash
python3 dataset/prompt-injection/gcg-supplement/hf-gcg/fetch_hf_gcg.py --limit 10000
python3 dataset/prompt-injection/gcg-supplement/hf-gcg/render_hf_gcg.py
python3 eval/combine_manifests.py
python3 dataset/prompt-injection/scripts/build_stats.py
```

Use `--dry-run --limit 100` to validate HuggingFace access without writing the
local seed file.
