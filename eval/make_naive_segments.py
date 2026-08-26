#!/usr/bin/env python3
"""make_naive_segments.py — emit the NAIVE detector view as a segments dump.

The naive condition of the view ablation: what a lazy `.eml` reader gets —
subject + the text/plain part when present (falling back to HTML-stripped text
only when there is no text/plain part). No hidden-HTML text, no plain/html
merge, no attachment or PDF text. URLs stay refanged (realistic), so the only
difference vs the canonical piguard segment dump is STRUCTURAL VISIBILITY.

Output has the same schema as `piguard-eval --dump-segments`, so the identical
harness (run_eval.py / llm-judge scripts) runs both conditions by just pointing
PIGUARD_SEGMENTS at the other file.

Usage: python eval/make_naive_segments.py   # from repo root or eval/
       -> eval/segments-naive.jsonl
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
os.chdir(REPO)

from eml_extract import extract  # noqa: E402


def main() -> None:
    out_path = os.path.join(HERE, "segments-naive.jsonl")
    n_err = 0
    with open(os.path.join(HERE, "combined_manifest.jsonl")) as fi, open(out_path, "w") as fo:
        for line in fi:
            entry = json.loads(line)
            rec: dict = {"id": entry["id"]}
            try:
                ex = extract(entry["eml_path"], base_dir=".")
                naive_body = ex.text.strip() or ex.text_from_html.strip()
                rec["segments"] = [
                    {"type": "subject", "content": ex.subject, "ref": "subject"},
                    {"type": "subject", "content": ex.from_, "ref": "from"},
                    {"type": "text_plain", "content": naive_body, "ref": "naive_body"},
                ]
            except Exception as e:  # mirror the canonical dump's error records
                rec["error"] = f"{type(e).__name__}: {e}"
                n_err += 1
            fo.write(json.dumps(rec) + "\n")
    print(f"wrote {out_path} (errors: {n_err})")


if __name__ == "__main__":
    main()
