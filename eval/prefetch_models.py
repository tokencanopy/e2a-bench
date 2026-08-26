#!/usr/bin/env python3
"""prefetch_models.py — download the ungated HF classifier weights into HF_HOME.

Run at image build time (BAKE_MODELS=1) so eval runs don't depend on
HuggingFace being reachable. Listed models are all permissively licensed and
ungated (Apache-2.0 / MIT) — no HF token required.
"""
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODELS = [
    "protectai/deberta-v3-base-prompt-injection-v2",
    "leolee99/InjecGuard",
    "fmops/distilbert-prompt-injection",
]

for model_id in MODELS:
    print(f"prefetch {model_id}", flush=True)
    AutoTokenizer.from_pretrained(model_id)
    AutoModelForSequenceClassification.from_pretrained(model_id)

print("prefetch complete")
