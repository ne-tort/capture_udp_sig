"""
Load per-profile slot policy from capture_policy.yaml (signature-lab).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "capture_policy.yaml"

_FALLBACK: Dict[str, Dict[str, Any]] = {
    "dns": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 5},
    "sip": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 5},
    "dtls": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 5},
    "quic": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 5},
    "quic_browser": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 5},
    "stun": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 2},
    "webrtc": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 2},
    "stun_browser": {"required_slots": ["i1"], "optional_slots": ["i2", "i3", "i4", "i5"], "max_slots": 2},
}


@lru_cache(maxsize=4)
def _load_policy_file(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def get_slot_policy(profile_id: str, *, policy_path: Optional[Path] = None) -> Dict[str, Any]:
    path = policy_path or _DEFAULT_POLICY
    raw = _load_policy_file(str(path.resolve() if path else _DEFAULT_POLICY))
    profiles = raw.get("profiles") if isinstance(raw.get("profiles"), dict) else {}
    base = dict(_FALLBACK.get(profile_id, {"required_slots": ["i1"], "max_slots": 5}))
    if profile_id in profiles and isinstance(profiles[profile_id], dict):
        base.update(profiles[profile_id])
    return base
