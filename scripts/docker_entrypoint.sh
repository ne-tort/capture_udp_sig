#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-quic_browser}"
TIMEOUT_ARG="${2:-}"
OUT="/lab/output/live_${PROFILE}.json"
DEBUG="/lab/output/live_${PROFILE}_debug.json"

mkdir -p /lab/output

echo "[capture] profile=${PROFILE}"

cd /lab
ARGS=(--profile "$PROFILE" --out "$OUT" --debug-out "$DEBUG")
if [[ -n "$TIMEOUT_ARG" ]]; then
  ARGS+=(--timeout "$TIMEOUT_ARG")
fi
python scripts/live_capture.py "${ARGS[@]}"

echo "[capture] prod  -> ${OUT}"
echo "[capture] debug -> ${DEBUG}"

python audit_capture.py --strict --profile "$PROFILE" \
  --out "/lab/output/audit_${PROFILE}.json" 2>/dev/null || true

python -c "
import json
from pathlib import Path
prod = json.loads(Path('${OUT}').read_text())
filled = [k for k in ('i1','i2','i3','i4','i5') if k in prod]
print('prod_slots', filled)
"
