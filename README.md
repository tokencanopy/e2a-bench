# e2a-bench

The benchmark and evaluation harness behind
**"e2a: A Secure Agent-Native Email Gateway with Phishing and Prompt-Injection Defense"**
(EMNLP 2026 System Demonstrations).

This repo is the artifact companion to the [e2a system repo](https://github.com/tokencanopy/e2a)
(the gateway itself, Apache-2.0, live at [e2a.dev](https://e2a.dev)). Everything the paper
measures lives here: the email corpus and manifests, the detector adapters, the LLM-judge
per-message scores, and the analysis script that prints Tables 1–2.

## Layout

| Path | What it is |
|---|---|
| [`dataset/`](dataset/) | The benchmark corpus: one test case = one `.eml` + one manifest record ([schema](dataset/schema/email_record.schema.json)). See [The corpus](#the-corpus) below. |
| [`eval/`](eval/) | The harness: detector adapters ([`eval/detectors/`](eval/detectors/)), runner ([`run_eval.py`](eval/run_eval.py)), grader ([`grade.py`](eval/grade.py)), and the paper's source of record, [`tier1_analysis.py`](eval/tier1_analysis.py). |
| [`eval/llm-judge/`](eval/llm-judge/) | The LLM-as-judge track: prompts, runner scripts, and the committed per-message Gemini predictions (text, naive-view, and image). Its [README](eval/llm-judge/README.md) documents every prompt/confidence/vision lever we tested. |
| [`eval/results/`](eval/results/) | Curated, committed metrics per detector run (`*/metrics.json` + a README each), incl. [`tier1-analysis/`](eval/results/tier1-analysis/) — the JSON behind Table 1 and the DMARC stratification. |

## The corpus

Two single-label detection tasks; full provenance and licenses in
[`dataset/sources/NOTES.md`](dataset/sources/NOTES.md).

- **Prompt injection** — 2,794 positive `.eml` (1,002 direct, 1,792 indirect):
  347 base payloads from InjecAgent, AgentDojo, and LLMail-Inject (all MIT) plus 58
  handcrafted `.eml`, rendered across **eight structural-hiding surfaces** (plaintext, visible HTML,
  CSS-hidden HTML, multipart mismatch, quoted-thread, header, PDF attachment,
  encoded/obfuscated) — the payload held constant so a detection drop is attributable to
  *structure*, not content. Negatives (2,039): 1,500 SpamAssassin ham, 339 NotInject
  over-defense probes, 200 structure-matched synthetic controls.
- **Phishing** — 3,000 balanced `.eml`: 1,500 SpamAssassin ham vs. 1,500 malicious —
  1,000 real phishing (Nazario, CC-BY-4.0, incl. 2020–2023 mailboxes) plus 500
  SpamAssassin spam. Both malicious splits grade as phishing-task positives
  (`threat_type` `phishing` and `spam`).

Every record carries an **assigned** `sender_auth_condition ∈ {verified, unauthenticated,
spoofed}` (PI positives balanced ⅓/⅓/⅓ by construction). It is a detector *feature*, never
a label: the schema and generation scripts deliberately stamp it rather than parse
`Authentication-Results`, because e2a recomputes SPF/DKIM/DMARC live and a 2005-era `.eml`
cannot carry a modern verdict. Synthetic material is stored with defanged URLs; the
public corpora are redistributed as published upstream (see [`DATA_LICENSE.md`](DATA_LICENSE.md)).

## Reproducing the paper's numbers

Tables 1–2 and Findings 1–5 come from four steps, run from the repo root.
Install deps with `pip install -r eval/requirements.txt` (the `torch`/`transformers` block
is only needed for the local HF classifiers, not for API detectors or the analysis step).

### Zero-effort setup: hand this to a coding agent

<details>
<summary>Copy-paste prompt for Claude Code / Codex / Cursor</summary>

```text
Set up the e2a-bench evaluation harness in this checkout and verify it reproduces
the committed LLM-judge results. Steps:

1. python3 -m venv .venv && ./.venv/bin/pip install numpy scikit-learn
   (that is enough for the analysis step; install -r eval/requirements.txt only
   if you also plan to run detectors — the torch/transformers block is heavy)
2. python3 eval/combine_manifests.py        # writes eval/combined_manifest.jsonl
3. ./.venv/bin/python eval/tier1_analysis.py
   It will print "predictions missing, skipped" for the OSS/commercial baselines
   (their per-message runs are not distributed) and still produce the judge rows.
4. Verify against the committed reference. PI-task judge rows: AUC
   0.98 / 0.96 / 0.98, TPR@1%FPR 0.799 / 0.920 / 0.811. Phishing-task judge
   rows: AUC 0.990 / 0.978 / 0.988, TPR@1%FPR 0.929 / 0.871 / 0.893 over
   1,500 positives. DMARC two-tier sweep: single 0.729 -> two-tier 0.887.
   Rerunning must not shrink results/tier1-analysis/table1_aligned.json —
   rows it cannot recompute are carried forward. Every point estimate should
   match the committed file exactly; only the bootstrap CIs of the recomputed
   phishing rows move (3rd-4th decimal), because the bootstrap draws from one
   shared RNG stream whose position depends on how many detectors ran.

Optional, to also regenerate the OSS baseline rows (no API keys, CPU only, slow):
5. Build the canonical segment dump (needs Go): clone
   https://github.com/tokencanopy/e2a, `go build -o piguard-eval-bin
   ./cmd/piguard-eval`, then run it with --dump-segments as shown in step 2 of
   the README, and export PIGUARD_SEGMENTS.
6. ./.venv/bin/pip install -r eval/requirements.txt, then run eval/run_eval.py
   with the detector flags from step 3 of the README, out-dir
   eval/runs/offline-oss, and re-run eval/tier1_analysis.py.

Do not fetch any dataset from the network; everything needed is committed.
Report the printed tables and whether step 4 matched.
```

</details>

### 1. Materialize the eval manifest

```bash
python3 eval/combine_manifests.py        # → eval/combined_manifest.jsonl
```

Merges PI positives + adaptive supplement with the ham, NotInject, and matched-control
negatives into one manifest (NotInject auto-included).

### 2. Dump the canonical detector view (needs the e2a system repo)

Every text detector screens **exactly what the gateway extracts** — subject, `text/plain`,
visible *and CSS-hidden* HTML split apart, encodings decoded, attachment text surfaced —
via the `piguard-eval` binary built from the e2a system repo:

```bash
cd <e2a-checkout> && go build -o ../piguard-eval-bin ./cmd/piguard-eval && cd -
export PIGUARD_EVAL_BIN=$PWD/piguard-eval-bin
"$PIGUARD_EVAL_BIN" --dump-segments --base-dir . \
    < eval/combined_manifest.jsonl > eval/segments.jsonl
export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl
```

Skipping this silently degrades the attachment/hidden surfaces (detectors fall back to a
body-only reparse). The *naive* view for the §Detector-input ablation is the same dump via
[`eval/make_naive_segments.py`](eval/make_naive_segments.py) → `segments-naive.jsonl`.
No Go toolchain? [`eval/Dockerfile`](eval/Dockerfile) builds a self-contained image and
pins the exact piguard revision evaluated in the paper (`--build-arg E2A_REF=…`);
[`eval/gcp/`](eval/gcp/) has the batch-VM scripts we used for the full runs.

### 3. Score detectors — or use the committed predictions

```bash
python3 eval/run_eval.py \
    --detectors piguard \
    --detectors hf:protectai/deberta-v3-base-prompt-injection-v2 \
    --detectors hf:leolee99/InjecGuard \
    --detectors hf:meta-llama/Llama-Prompt-Guard-2-86M \
    --detectors hf:fmops/distilbert-prompt-injection \
    --manifest eval/combined_manifest.jsonl --base-dir . \
    --out-dir eval/runs/offline-oss
```

Predictions stream to `eval/runs/<name>/<detector>.jsonl` (incremental, resumable);
[`ensemble_predictions.py`](eval/ensemble_predictions.py) then builds the mean-score OSS
ensemble row. API detectors and their credentials:

| Detector flag | Needs |
|---|---|
| `llm` / `llm-vision` (Gemini judges) | `GEMINI_API_KEY` |
| `lakera` | `LAKERA_API_KEY` |
| `scamguard` | `SCAMGUARD_API_KEY` (endpoint: [`eval/detectors/scamguard.py`](eval/detectors/scamguard.py)) |
| `modelarmor` | GCP creds + `MODELARMOR_PROJECT` (see [`eval/detectors/modelarmor.py`](eval/detectors/modelarmor.py)) |

**The Gemini-judge per-message scores are committed** under
[`eval/llm-judge/results/`](eval/llm-judge/results/) (`matrix/` text, `matrix-naive/`,
`matrix-image/`) — each row is a numeric score keyed to a corpus id, no email text — so the
judge rows of Table 1 are re-derivable exactly even after the underlying models drift.
Per-message scores for the OSS and commercial detectors are **not** distributed (the
commercial APIs' raw outputs are theirs to publish, not ours); regenerate them with step 3
above — the OSS classifiers run locally for free, the commercial rows need your own API
keys. Aggregate metrics for every detector are committed under
[`eval/results/`](eval/results/).

### 4. Analyze

```bash
python3 eval/tier1_analysis.py
```

This is the **source of record for Table 1 and Findings 1–5**: it scores every detector on
the identical text population (5,955 ids; the PDF surface is held out to the vision track),
splits dev/test 50/50 **grouped by base payload** (all renderings of one lure land on one
side), reads headline metrics on the held-out test half (1,217 PI vs 1,003 benign), and
reports payload-clustered bootstrap CIs. It also runs the sender-auth (DMARC) two-tier
threshold sweep — tuned on dev only, read once on test — and the canonical-vs-naive view
ablation. Outputs land in `eval/results/tier1-analysis/*.json`.

Table 2 (per-surface AUC) comes from the curated per-detector runs:
[`grade.py`](eval/grade.py) with `--slice surface`, summarized per detector in
[`eval/results/*/metrics.json`](eval/results/) (see each run's README for its exact
protocol and caveats — e.g. ScamGuard is run off-label on the PI task).

## Notes for reviewers / reusers

- **Committed vs. regenerated**: `.eml` corpus, manifests, judge per-message scores, and
  curated aggregate metrics are committed; `eval/combined_manifest.jsonl`,
  `segments*.jsonl`, and the OSS/commercial per-message runs are regenerated
  (steps 1–3).
- **Scanning is off by default in the live system.** A default e2a deployment (including
  self-host) runs the gateway layer only: `E2A_CONTENT_SCAN_ENABLED` defaults to `false`,
  and even with it set to `true`, each agent's scan starts at `off` until raised via
  `PUT /v1/agents/{email}/protection` (`scan_sensitivity` = `low`/`medium`/`high`). Adding
  `GEMINI_API_KEY` attaches the LLM-judge layer on top of the built-in piguard heuristics.
  See the [deployment doc](https://github.com/tokencanopy/e2a/blob/main/docs/deployment.md)
  in the system repo. The numbers in this benchmark are therefore an evaluation of the
  detection layers, not a description of default deployed behavior.
- **Rerunning step 4 is non-destructive.** Without the OSS/commercial per-message
  predictions the analysis can only recompute the judge rows; it carries every other
  detector's row forward from the committed file rather than dropping it, so
  `eval/results/tier1-analysis/*.json` stays the complete record behind Table 1. Rows
  are only carried forward when the population signature matches — change the corpus
  and the stale rows are dropped with a printed warning instead.
- **Metrics philosophy** (why TPR@1%FPR leads and a lone 0.35 threshold doesn't):
  [`eval/EVAL_METHODOLOGY.md`](eval/EVAL_METHODOLOGY.md).
- **Redistribution**: Nazario (CC-BY-4.0), SpamAssassin (redistributable), and the MIT
  payload suites are committed with attribution; CyberSecEval3 images are **not**
  redistributed (dataset card: evaluation-only) — [`dataset/prompt-injection/image-pi-email/build.py`](dataset/prompt-injection/image-pi-email/build.py)
  re-downloads them. Summary: [`DATA_LICENSE.md`](DATA_LICENSE.md); details: [`dataset/sources/NOTES.md`](dataset/sources/NOTES.md).
- **Ethics**: attacks reproduce already-public techniques and CVEs; synthetic material is
  defanged, public corpora are redistributed as published upstream (do not resolve the
  URLs); the corpus is released for defense research.
