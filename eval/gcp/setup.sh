#!/usr/bin/env bash
# One-time GCP infra setup: enable APIs, create Artifact Registry repo, results
# bucket, and API-key secrets. Idempotent — safe to re-run.
#
#   cd e2a-bench && bash eval/gcp/setup.sh
#
# API keys are read from your current shell env if present:
#   GEMINI_API_KEY, LAKERA_API_KEY
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
source eval/gcp/config.env

echo ">> enabling APIs"
gcloud services enable \
  compute.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  --project="$PROJECT_ID"

echo ">> Artifact Registry repo: $AR_REPO"
gcloud artifacts repositories describe "$AR_REPO" \
  --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1 || \
gcloud artifacts repositories create "$AR_REPO" \
  --repository-format=docker --location="$REGION" \
  --description="e2a eval images" --project="$PROJECT_ID"

echo ">> results bucket: gs://$BUCKET"
gcloud storage buckets describe "gs://$BUCKET" --project="$PROJECT_ID" >/dev/null 2>&1 || \
gcloud storage buckets create "gs://$BUCKET" \
  --location="$REGION" --project="$PROJECT_ID"

create_secret () {
  local name="$1" value="$2"
  [ -z "$value" ] && { echo "   skip $name (not set in env)"; return; }
  if gcloud secrets describe "$name" --project="$PROJECT_ID" >/dev/null 2>&1; then
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- --project="$PROJECT_ID"
    echo "   updated $name"
  else
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- --project="$PROJECT_ID"
    echo "   created $name"
  fi
}

echo ">> secrets (from your shell env)"
create_secret GEMINI_API_KEY "${GEMINI_API_KEY:-}"
create_secret LAKERA_API_KEY "${LAKERA_API_KEY:-}"

echo ">> done."
