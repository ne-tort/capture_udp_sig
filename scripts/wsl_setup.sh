#!/usr/bin/env bash
# One-time / repeat WSL setup for signature-lab live capture.
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUDO_PW="${SIGNATURE_LAB_SUDO_PW:-112233}"

sudo_cmd() {
  echo "$SUDO_PW" | sudo -S "$@" 2>/dev/null
}

echo "[setup] apt packages (tcpdump, dig, build deps)..."
sudo_cmd apt-get update -qq
sudo_cmd apt-get install -y -qq \
  tcpdump dnsutils libpcap-dev python3-venv curl ca-certificates

echo "[setup] allow tcpdump without password prompt (setcap)..."
TCPDUMP_BIN="$(command -v tcpdump)"
if [ -n "$TCPDUMP_BIN" ]; then
  sudo_cmd setcap cap_net_raw,cap_net_admin+eip "$TCPDUMP_BIN" || true
  getcap "$TCPDUMP_BIN" 2>/dev/null || true
fi

echo "[setup] poetry install..."
cd "$LAB_ROOT"
poetry install -q

echo "[setup] playwright chromium..."
poetry run playwright install chromium

echo "[setup] verify imports..."
poetry run python -c "import yaml, scapy; from browser_capture.core.orchestrator import CaptureOrchestrator; print('ok')"

echo "[setup] done."
