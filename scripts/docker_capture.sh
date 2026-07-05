#!/usr/bin/env bash
# Live capture — only Docker required (no Poetry/Python on host).
# Usage: ./scripts/docker_capture.sh [profile] [timeout_sec]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${1:-dns}"
TIMEOUT="${2:-}"
IMAGE="capture-udp-sig"
BROWSER_PROFILES="quic quic_browser quic_tls_browser stun stun_browser webrtc"
DOCKERFILE="Dockerfile.capture-lite"
for p in $BROWSER_PROFILES; do
  if [[ "$PROFILE" == "$p" ]]; then
    DOCKERFILE="Dockerfile.capture"
    break
  fi
done

mkdir -p output

export DOCKER_BUILDKIT=1
echo "=== docker build $IMAGE ($DOCKERFILE) ==="
docker build -f "$DOCKERFILE" -t "$IMAGE" .

RUN=(run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$ROOT/output:/lab/output" "$IMAGE" "$PROFILE")
if [[ -n "$TIMEOUT" ]]; then
  RUN+=("$TIMEOUT")
fi

echo "=== capture profile=$PROFILE ==="
docker "${RUN[@]}"

OUT="$ROOT/output/live_${PROFILE}.json"
if [[ ! -f "$OUT" ]]; then
  echo "Missing $OUT" >&2
  exit 1
fi

echo ""
echo "=== result ($OUT) ==="
cat "$OUT"
