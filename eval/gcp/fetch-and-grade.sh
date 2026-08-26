#!/usr/bin/env bash
# Pull a run's predictions from GCS and grade them locally.
#   cd e2a-bench && bash eval/gcp/fetch-and-grade.sh RUN_ID [--slice surface]
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
source eval/gcp/config.env

RUN_ID="${1:?usage: fetch-and-grade.sh RUN_ID [grade.py args...]}"
shift || true

LOCAL="eval/runs/${RUN_ID}"
mkdir -p "$LOCAL"
echo ">> fetching gs://$BUCKET/runs/$RUN_ID → $LOCAL"
gsutil -m rsync -r "gs://${BUCKET}/runs/${RUN_ID}" "$LOCAL"

echo ">> grading"
python3 eval/grade.py --run-dir "$LOCAL" "$@"
