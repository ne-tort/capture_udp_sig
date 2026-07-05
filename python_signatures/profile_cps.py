"""
Per-profile CPS merge for I1-I5.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from python_signatures.provenance import (
    SLOT_KEYS,
    classify_slot,
    raw_capture_value,
)

SLOT_TAIL = ("i2", "i3", "i4", "i5")

_KNOWN = frozenset({
    "dns", "sip", "sip_multi", "dtls", "ntp",
    "quic", "quic_browser", "quic_tls_browser",
    "stun", "webrtc", "stun_browser",
})


def obfs_r_bytes() -> int:
    return int(os.environ.get("OBFS_R_BYTES", "48"), 10)


@dataclass
class MergeResult:
    i1: str = ""
    i2: Optional[str] = None
    i3: Optional[str] = None
    i4: Optional[str] = None
    i5: Optional[str] = None
    slot_sources: Dict[str, str] = field(default_factory=dict)
    incomplete_slots: List[str] = field(default_factory=list)

    def to_profile_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "slot_sources": dict(self.slot_sources),
            "incomplete_slots": list(self.incomplete_slots),
        }
        for slot in SLOT_KEYS:
            val = getattr(self, slot)
            if isinstance(val, str) and val.strip():
                out[slot] = val.strip()
        return out

    def to_legacy_dict(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for slot in SLOT_KEYS:
            val = getattr(self, slot)
            if isinstance(val, str) and val.strip():
                out[slot] = val.strip()
        return out


def _validate_hex(sig: Dict[str, Any]) -> str:
    hex_val = sig.get("hex")
    if not isinstance(hex_val, str) or not hex_val.strip().startswith("<b 0x"):
        raise ValueError("signature must have hex (I1) starting with <b 0x")
    return hex_val.strip()


def _ensure_known_profile(profile_id: str) -> None:
    if profile_id not in _KNOWN:
        raise ValueError(f"unknown profile_id={profile_id!r}")


def merge_collector_output_strict(
    profile_id: str,
    sig: Dict[str, Any],
    *,
    allow_template_fallback: bool = False,
    required_slots: Optional[List[str]] = None,
) -> MergeResult:
    hex_val = _validate_hex(sig)
    _ensure_known_profile(profile_id)

    result = MergeResult(i1=hex_val)
    result.slot_sources["i1"] = classify_slot(profile_id, sig, "i1", merged_value=hex_val)

    for slot in SLOT_TAIL:
        raw = raw_capture_value(sig, slot)
        if raw:
            setattr(result, slot, raw)
            result.slot_sources[slot] = classify_slot(
                profile_id, sig, slot, merged_value=raw
            )
        else:
            result.slot_sources[slot] = "missing"

    if allow_template_fallback:
        from python_signatures.template_pool import pick_random_entry

        tpl = pick_random_entry(profile_id) or {}
        for slot in SLOT_KEYS:
            val = result.i1 if slot == "i1" else getattr(result, slot)
            if not (isinstance(val, str) and val.strip()) and tpl.get(slot):
                if slot == "i1":
                    result.i1 = tpl[slot]
                else:
                    setattr(result, slot, tpl[slot])
                result.slot_sources[slot] = "template_pool"

    check_slots = required_slots if required_slots is not None else list(SLOT_KEYS)
    result.incomplete_slots = []
    for slot in check_slots:
        val = result.i1 if slot == "i1" else getattr(result, slot)
        if not (isinstance(val, str) and val.strip()):
            result.incomplete_slots.append(slot)
    return result


def merge_collector_output(
    profile_id: str,
    sig: Dict[str, Any],
    *,
    allow_template_fallback: bool = True,
) -> Dict[str, str]:
    mr = merge_collector_output_strict(
        profile_id, sig, allow_template_fallback=allow_template_fallback
    )
    return mr.to_legacy_dict()
