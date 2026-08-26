# GCG-style suffix supplement

Small deterministic supplement for evaluating detectors that target adversarial
suffix attacks: a natural email/prompt followed by a high-entropy punctuation
suffix resembling GCG-style optimizer output.

This slice is intentionally separate from the main prompt-injection benchmark so
it can be reported on its own. It includes malicious suffix cases and benign hard
negatives with technical-looking tails such as logs, URLs, UUIDs, code, and
base64-like text.

Build:

```bash
python3 dataset/prompt-injection/gcg-supplement/render_gcg.py
python3 eval/combine_manifests.py
```

