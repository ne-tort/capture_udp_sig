"""
Per-profile CPS merge for I1-I5 (signature-lab).

Strict mode (default): no Architect fallback unless ``allow_architect=True``.
Always records ``slot_sources`` and ``incomplete_slots``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from python_signatures.architect_fallbacks import ARCHITECT_DEFAULTS
from python_signatures.provenance import (
    SLOT_KEYS,
    classify_slot,
    raw_capture_value,
)

SLOT_TAIL = ("i2", "i3", "i4", "i5")


def obfs_r_bytes() -> int:
    """Legacy helper for tooling that still reads ``OBFS_R_BYTES`` from the environment."""
    return int(os.environ.get("OBFS_R_BYTES", "48"), 10)


@dataclass
class MergeResult:
    """Full merge output with provenance."""

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
        """Flat i1..i5 map (only filled slots)."""
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


def _ensure_arch_bundle(profile_id: str) -> Dict[str, str]:
    arch = ARCHITECT_DEFAULTS.get(profile_id)
    if arch is None:
        raise ValueError(
            f"unknown profile_id={profile_id!r}; add ARCHITECT_DEFAULTS entry"
        )
    for key in SLOT_TAIL:
        if key not in arch:
            raise ValueError(f"ARCHITECT_DEFAULTS[{profile_id!r}] must define {key!r}")
    return arch


def merge_collector_output_strict(
    profile_id: str,
    sig: Dict[str, Any],
    *,
    allow_architect: bool = False,
    required_slots: Optional[List[str]] = None,
) -> MergeResult:
    """
    Build merge result with provenance.

    - ``allow_architect=False`` (default): missing slots stay empty → ``incomplete_slots``.
    - ``allow_architect=True``: fill gaps from ARCHITECT_DEFAULTS, source=architect.
    - ``required_slots``: if set, only these slots must be filled for completeness check.
    """
    hex_val = _validate_hex(sig)
    arch = _ensure_arch_bundle(profile_id)

    result = MergeResult(i1=hex_val)
    result.slot_sources["i1"] = classify_slot(
        profile_id, sig, "i1", merged_value=hex_val, allow_architect=allow_architect
    )

    for slot in SLOT_TAIL:
        raw = raw_capture_value(sig, slot)
        if raw:
            setattr(result, slot, raw)
            result.slot_sources[slot] = classify_slot(
                profile_id, sig, slot, merged_value=raw, allow_architect=allow_architect
            )
        elif allow_architect:
            val = arch[slot]
            setattr(result, slot, val)
            result.slot_sources[slot] = "architect"
        else:
            result.slot_sources[slot] = "missing"

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
    allow_architect: bool = True,
) -> Dict[str, str]:
    """Legacy flat merge (all five slots when allow_architect=True)."""
    mr = merge_collector_output_strict(profile_id, sig, allow_architect=allow_architect)
    out: Dict[str, str] = {"i1": mr.i1}
    for slot in SLOT_TAIL:
        val = getattr(mr, slot)
        if isinstance(val, str) and val.strip():
            out[slot] = val.strip()
        elif allow_architect:
            out[slot] = ARCHITECT_DEFAULTS[profile_id][slot]
    return out
