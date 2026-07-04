"""
CPS builder: hybrid static bytes + random/timestamp tags (signature-lab).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from python_signatures.base import SignatureCollector


class FieldKind(str, Enum):
    STATIC = "static"
    RANDOM_BYTES = "random_bytes"
    RANDOM_ASCII = "random_ascii"
    RANDOM_DIGITS = "random_digits"
    TIMESTAMP = "timestamp"


@dataclass
class FieldSpec:
    offset: int
    length: int
    kind: FieldKind

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "FieldSpec":
        return cls(
            offset=int(raw["offset"]),
            length=int(raw["length"]),
            kind=FieldKind(str(raw["kind"])),
        )


def payload_to_cps(payload: bytes, fields: List[FieldSpec]) -> str:
    """Build CPS string from payload regions."""
    parts: List[str] = []
    for f in fields:
        chunk = payload[f.offset : f.offset + f.length]
        if f.kind == FieldKind.STATIC:
            parts.append(SignatureCollector.format_signature(chunk))
        elif f.kind == FieldKind.RANDOM_BYTES:
            parts.append(f"<r {f.length}>")
        elif f.kind == FieldKind.RANDOM_ASCII:
            parts.append(f"<rc {f.length}>")
        elif f.kind == FieldKind.RANDOM_DIGITS:
            parts.append(f"<rd {f.length}>")
        elif f.kind == FieldKind.TIMESTAMP:
            parts.append("<t>")
    return "".join(parts)


def load_cps_spec(profile_id: str, specs_dir: Optional[Path] = None) -> List[FieldSpec]:
    base = specs_dir or Path(__file__).resolve().parent / "cps_specs"
    path = base / f"{profile_id}.yaml"
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    slots = data.get("slots", {})
    # Return first slot spec list for API simplicity; per-slot via load_slot_spec
    return []


def load_slot_spec(profile_id: str, slot: str, specs_dir: Optional[Path] = None) -> List[FieldSpec]:
    base = specs_dir or Path(__file__).resolve().parent / "cps_specs"
    path = base / f"{profile_id}.yaml"
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    slots = data.get("slots", {})
    if not isinstance(slots, dict) or slot not in slots:
        return []
    raw_fields = slots[slot]
    if not isinstance(raw_fields, list):
        return []
    return [FieldSpec.from_dict(x) for x in raw_fields if isinstance(x, dict)]


def _pure_b_payload(cps: str) -> Optional[bytes]:
    """Extract bytes only from a single ``<b 0xHEX>`` CPS string (no other tags)."""
    if not isinstance(cps, str):
        return None
    s = cps.strip()
    if not s.lower().startswith("<b 0x"):
        return None
    end = s.find(">")
    if end < 0:
        return None
    if s[end + 1 :].strip():
        return None
    hex_part = s[5:end].strip()
    try:
        return bytes.fromhex(hex_part)
    except ValueError:
        return None


def apply_cps_specs_to_sig(profile_id: str, sig: Dict[str, Any]) -> Dict[str, Any]:
    """
    If cps_specs exist, synthesize CPS for raw single-`<b>` slots from payload bytes.
    Sets ``_cps_synth_slots`` for provenance.
    """
    out = dict(sig)
    synth: List[str] = []

    payload = _pure_b_payload(str(out.get("hex", "")))
    if payload is not None:
        fields = load_slot_spec(profile_id, "i1")
        if fields:
            out["hex"] = payload_to_cps(payload, fields)
            synth.append("i1")

    for slot in ("i2", "i3", "i4", "i5"):
        val = out.get(slot)
        payload = _pure_b_payload(str(val)) if val else None
        if payload is None:
            continue
        fields = load_slot_spec(profile_id, slot)
        if fields:
            out[slot] = payload_to_cps(payload, fields)
            synth.append(slot)

    if synth:
        out["_cps_synth_slots"] = synth
    return out
