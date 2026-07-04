"""Per-profile live capture timeouts (seconds) — minimal adequate values."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml

_DEFAULTS: Dict[str, int] = {
    "quic_browser": 30,
    "quic": 30,
    "quic_tls_browser": 30,
    "stun_browser": 15,
    "stun": 15,
    "webrtc": 15,
    "dns": 12,
    "sip": 15,
    "sip_multi": 18,
    "dtls": 18,
    "ntp": 10,
}

_POLICY = Path(__file__).resolve().parent.parent / "capture_policy.yaml"


@lru_cache(maxsize=2)
def _load_policy(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def get_capture_timeout(profile_id: str, *, override: int | None = None) -> int:
    if override is not None and override > 0:
        return override
    raw = _load_policy(str(_POLICY))
    profiles = raw.get("profiles") if isinstance(raw.get("profiles"), dict) else {}
    prof = profiles.get(profile_id) if isinstance(profiles.get(profile_id), dict) else {}
    t = prof.get("capture_timeout_sec")
    if isinstance(t, int) and t > 0:
        return t
    return _DEFAULTS.get(profile_id, 15)
