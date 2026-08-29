# Self-contained image for the e2a prompt-injection eval pipeline.
#
# Build from the e2a-bench repo root (so dataset/ and eval/ are in context):
#   docker build -f eval/Dockerfile -t e2a-eval:latest .
#
# Pin the piguard source so the heuristics engine is reproducible:
#   docker build -f eval/Dockerfile \
#       --build-arg E2A_REF=b33566e \
#       --build-arg BAKE_MODELS=1 \
#       -t e2a-eval:latest .
#
# ---------------------------------------------------------------------------
# Stage 1 — build the piguard-eval Go binary from the (OSS) e2a repo.
# ---------------------------------------------------------------------------
FROM golang:1.25-bookworm AS go-builder

ARG E2A_REPO=https://github.com/Mnexa-AI/e2a.git
# Pinned to e2a@fe60124 (PR #305 squash-merged to main) — the commit that adds
# cmd/piguard-eval. Override with --build-arg E2A_REF=<sha> when re-evaluating a
# newer engine.
ARG E2A_REF=fe60124b4224075669fcd272f395697ec9c5a52f

RUN git clone "${E2A_REPO}" /src/e2a
WORKDIR /src/e2a
RUN git checkout "${E2A_REF}"
# CGO off → a static binary that runs in the slim runtime stage.
RUN CGO_ENABLED=0 go build -o /out/piguard-eval ./cmd/piguard-eval

# ---------------------------------------------------------------------------
# Stage 2 — Python runtime with the eval harness + datasets.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# CPU-only by default. For GPU, swap the base for an nvidia/cuda image and
# install the matching torch wheel (see eval/gcp/README.md).
ENV PIP_NO_CACHE_DIR=1 \
    HF_HOME=/models \
    PIGUARD_EVAL_BIN=/usr/local/bin/piguard-eval \
    PIGUARD_SEGMENTS=/app/eval/segments.jsonl \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps: none beyond what the slim image has, except ca-certs for HTTPS.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps. Torch from the CPU wheel index to avoid the CUDA payload.
COPY eval/requirements.txt /app/requirements.txt
RUN pip install torch>=2.2.0 --index-url https://download.pytorch.org/whl/cpu \
    && pip install -r /app/requirements.txt

# The piguard heuristics binary from stage 1.
COPY --from=go-builder /out/piguard-eval /usr/local/bin/piguard-eval

# The eval harness and the datasets (eml + manifests).
COPY eval/ /app/eval/
COPY dataset/ /app/dataset/

# Bake the canonical shared detector view from the frozen paper population so
# every in-container text detector sees exactly the same extracted segments.
RUN /usr/local/bin/piguard-eval --dump-segments --base-dir /app \
    < eval/paper_manifest.jsonl > eval/segments.jsonl

# Optionally pre-bake the three ungated HF classifiers into the image so runs
# don't depend on HuggingFace being reachable at runtime (reliability).
ARG BAKE_MODELS=0
RUN if [ "$BAKE_MODELS" = "1" ]; then python3 eval/prefetch_models.py; fi

# Default: print help. The run script overrides the command.
ENTRYPOINT ["python3", "eval/run_eval.py"]
CMD ["--help"]
