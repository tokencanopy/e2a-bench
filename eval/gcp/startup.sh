#!/usr/bin/env bash
# Runs on the eval VM at boot (passed via startup-script metadata).
# Pulls the image, fetches API keys from Secret Manager, runs the detectors,
# syncs predictions to GCS, then (optionally) deletes the VM.
set -euxo pipefail

md() { curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/$1"; }

IMAGE=$(md instance/attributes/image)
BUCKET=$(md instance/attributes/bucket)
DETECTORS=$(md instance/attributes/detectors)
REGION=$(md instance/attributes/region)
RUN_ID=$(md instance/attributes/run-id)
DELETE_SELF=$(md instance/attributes/delete-self)
PROJECT=$(md project/project-id)
ZONE=$(md instance/zone | awk -F/ '{print $NF}')
NAME=$(md instance/name)

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io curl apt-transport-https ca-certificates gnupg

# Google Cloud CLI (for Secret Manager + GCS + Artifact Registry auth).
echo "deb https://packages.cloud.google.com/apt cloud-sdk main" \
  > /etc/apt/sources.list.d/google-cloud-sdk.list
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
  | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
sed -i 's|deb |deb [signed-by=/usr/share/keyrings/cloud.google.gpg] |' \
  /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y google-cloud-cli

# Pull the eval image from Artifact Registry.
gcloud auth configure-docker "${REGION}-docker.pkg.dev" -q
docker pull "$IMAGE"

# Fetch API keys (absent secrets → empty → that detector self-skips).
sec() { gcloud secrets versions access latest --secret="$1" --project="$PROJECT" 2>/dev/null || true; }
GEMINI_API_KEY=$(sec GEMINI_API_KEY)
LAKERA_API_KEY=$(sec LAKERA_API_KEY)

OUT="/var/eval-out/${RUN_ID}"
mkdir -p "$OUT"

# Resume: pull any prior partial results for this run id so run_eval.py skips
# already-completed ids (works even if the previous VM was deleted).
gsutil -m rsync -r "gs://${BUCKET}/runs/${RUN_ID}" "$OUT" 2>/dev/null || true

# Assemble --detectors flags.
DET_FLAGS=()
for d in $DETECTORS; do DET_FLAGS+=(--detectors "$d"); done

# Run. --network host so the container reaches the metadata server for Model
# Armor ADC. The image's ENTRYPOINT is run_eval.py.
docker run --rm --network host \
  -e GEMINI_API_KEY="$GEMINI_API_KEY" \
  -e LAKERA_API_KEY="$LAKERA_API_KEY" \
  -e MODELARMOR_PROJECT="$PROJECT" \
  -v "$OUT":/app/eval/runs/gcp \
  "$IMAGE" \
  "${DET_FLAGS[@]}" \
  --manifest eval/paper_manifest.jsonl \
  --out-dir eval/runs/gcp

# Persist results (rerunnable: rsync is incremental).
gsutil -m rsync -r "$OUT" "gs://${BUCKET}/runs/${RUN_ID}"

if [ "$DELETE_SELF" = "1" ]; then
  gcloud compute instances delete "$NAME" --zone "$ZONE" -q
fi
