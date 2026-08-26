#!/usr/bin/env bash
# Create a VM that runs the eval once and syncs results to GCS.
#   cd e2a-bench && bash eval/gcp/run-vm.sh [RUN_ID]
# RUN_ID defaults to a timestamp; pass an explicit one to resume into the same
# GCS prefix (the harness skips already-completed predictions).
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
source eval/gcp/config.env

RUN_ID="${1:-run-$(date +%Y%m%d-%H%M%S)}"

echo ">> creating VM $VM_NAME  (run-id=$RUN_ID)"
gcloud compute instances create "$VM_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=50GB \
  --scopes=cloud-platform \
  --metadata=image="$IMAGE",bucket="$BUCKET",detectors="$DETECTORS",region="$REGION",run-id="$RUN_ID",delete-self="$DELETE_SELF" \
  --metadata-from-file=startup-script=eval/gcp/startup.sh

cat <<EOF

VM launched. Track progress:
  gcloud compute instances get-serial-port-output $VM_NAME --zone $ZONE --project $PROJECT_ID | tail -50

Results land in: gs://$BUCKET/runs/$RUN_ID
When done (VM self-deletes if DELETE_SELF=1), fetch + grade:
  bash eval/gcp/fetch-and-grade.sh $RUN_ID
EOF
