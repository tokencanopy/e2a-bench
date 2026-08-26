# Running the eval pipeline on GCP

This runs the full prompt-injection detection eval in a reproducible GCP
container: the piguard heuristics engine, the three local HuggingFace
classifiers, and the API detectors (Claude, Gemini, Lakera, Model Armor).

The design favors **reliability over speed**:

- The image is **self-contained and pinned** — it clones `e2a` at a fixed
  commit, builds `piguard-eval`, bakes the three HF model weights, and bakes the
  combined manifest. A run depends on nothing external except the API endpoints.
- The harness writes **incrementally and resumes** — a crash mid-run loses
  nothing; re-launching with the same `RUN_ID` continues where it stopped and
  retries only the entries that errored.
- API errors are **retried with backoff** before being recorded as failures.

## Architecture

```
Cloud Build ── builds ──► Artifact Registry (e2a-eval image)
                                   │
                          run-vm.sh creates VM
                                   │
        Debian VM (startup.sh): pull image, fetch keys from Secret Manager,
        docker run run_eval.py over all detectors, rsync results ──► GCS
                                   │
                     fetch-and-grade.sh ◄── pulls + grades locally
```

## Detectors

| Name | Where it runs | Needs |
|---|---|---|
| `piguard` | in-container Go binary | nothing |
| `hf:protectai/deberta-v3-base-prompt-injection-v2` | in-container (CPU) | nothing (baked) |
| `hf:leolee99/InjecGuard` | in-container (CPU) | nothing (baked) |
| `hf:fmops/distilbert-prompt-injection` | in-container (CPU) | nothing (baked) |
| `llm` | Anthropic API | `ANTHROPIC_API_KEY` secret |
| `gemini` | Google AI API | `GEMINI_API_KEY` secret |
| `lakera` | Lakera API | `LAKERA_API_KEY` secret |
| `modelarmor` | GCP Model Armor | VM service-account perms + a template |

A detector whose key/secret is missing self-skips with a logged message — it
won't fail the run.

## One-time setup

```bash
cd e2a-bench
cp eval/gcp/config.env.example eval/gcp/config.env
$EDITOR eval/gcp/config.env          # set PROJECT_ID, BUCKET, etc.

# Put your API keys in the shell, then create the GCP infra + secrets:
export ANTHROPIC_API_KEY=sk-ant-...
export GEMINI_API_KEY=...
export LAKERA_API_KEY=...
bash eval/gcp/setup.sh               # enables APIs, makes AR repo + bucket + secrets
```

## Build the image

```bash
bash eval/gcp/build-push.sh          # Cloud Build → Artifact Registry (~10-15 min w/ model bake)
```

This builds entirely in GCP — no local Docker needed. Pin the piguard source by
setting `E2A_REF` in `config.env` (e.g. a commit SHA) for a citable artifact.

## Run

```bash
bash eval/gcp/run-vm.sh                       # uses DETECTORS from config.env
# or a custom run id (also the resume handle):
bash eval/gcp/run-vm.sh run-2026-06-24-final
```

Watch progress on the serial console:

```bash
gcloud compute instances get-serial-port-output e2a-eval-runner \
  --zone "$ZONE" --project "$PROJECT_ID" | tail -50
```

The VM self-deletes when finished if `DELETE_SELF=1`.

### Resuming a failed run

Re-run `run-vm.sh` with the **same** `RUN_ID`. `startup.sh` first rsyncs that
run's existing GCS prefix back down onto the fresh VM, then `run_eval.py` skips
ids that already have a non-error prediction. So even though the previous VM
self-deleted, relaunching with the same id re-runs only the missing or errored
entries.

## Fetch results and grade

```bash
bash eval/gcp/fetch-and-grade.sh run-2026-06-24-final
bash eval/gcp/fetch-and-grade.sh run-2026-06-24-final --slice surface
bash eval/gcp/fetch-and-grade.sh run-2026-06-24-final --slice threat_type
```

Predictions land in `eval/runs/<RUN_ID>/<detector>.jsonl` plus
`manifest_used.jsonl` and `metrics.json`.

## Cost

CPU inference of the small models is cheap. An `e2-standard-4` is ~$0.13/hr
on-demand; the whole eval (all detectors) finishes well under an hour, so a run
is a few cents of compute plus the API-call costs for the hosted detectors.
For a faster build, set `BAKE_MODELS=0` (models download at first run instead).

## GPU (optional)

The HF models are small enough that CPU is fine. If you want GPU anyway, change
the runtime base image in `eval/Dockerfile` to an `nvidia/cuda` image, install
the matching torch CUDA wheel, and create the VM with `--accelerator` +
`--maintenance-policy=TERMINATE` and a GPU-enabled image. Not needed for
correctness — only speed.

## Local alternative

You don't need GCP to run this. From the repo root, with the piguard binary
built and keys exported:

```bash
go build -o /tmp/piguard-eval ../e2a/cmd/piguard-eval   # adjust path
export PIGUARD_EVAL_BIN=/tmp/piguard-eval
pip install -r eval/requirements.txt
python3 eval/combine_manifests.py
python3 eval/run_eval.py \
  --detectors piguard \
  --detectors hf:protectai/deberta-v3-base-prompt-injection-v2 \
  --out-dir eval/runs/local
python3 eval/grade.py --run-dir eval/runs/local
```

GCP's advantage is a clean, pinned, reproducible environment for the paper's
artifact — not raw speed.
