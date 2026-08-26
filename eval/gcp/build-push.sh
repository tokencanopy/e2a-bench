#!/usr/bin/env bash
# Build the eval image with Cloud Build and push to Artifact Registry.
#   cd e2a-bench && bash eval/gcp/build-push.sh
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
source eval/gcp/config.env

echo ">> Cloud Build → $IMAGE  (e2a@$E2A_REF, bake_models=$BAKE_MODELS)"
gcloud builds submit \
  --project="$PROJECT_ID" \
  --config=eval/gcp/cloudbuild.yaml \
  --substitutions="_IMAGE=${IMAGE},_E2A_REF=${E2A_REF},_BAKE_MODELS=${BAKE_MODELS}" \
  .

echo ">> pushed $IMAGE"
