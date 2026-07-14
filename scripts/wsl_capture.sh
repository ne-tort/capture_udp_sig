#!/usr/bin/env bash
# Live capture in WSL: tcpdump via setcap (no interactive sudo).
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-quic_browser}"
TIMEOUT="${2:-60}"
IFACE="${CAPTURE_IFACE:-any}"

cd "$LAB_ROOT"

if ! getcap "$(command -v tcpdump)" 2>/dev/null | grep -q cap_net_raw; then
  echo "Run: SIGNATURE_LAB_SUDO_PW=112233 bash scripts/wsl_setup.sh" >&2
  exit 1
fi

export CAPTURE_IFACE="$IFACE"
poetry run python scripts/live_capture.py --strict --profile "$PROFILE" --timeout "$TIMEOUT" \
  --out "output/live_${PROFILE}.json"
