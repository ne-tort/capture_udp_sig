"""
Convert capture outputs to panel / lab / conf formats.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from python_signatures.provenance import SLOT_KEYS, export_for_panel, export_prod_profile

ProfileMap = Dict[str, Any]
PanelMap = Dict[str, ProfileMap]


def prod_to_profile_map(prod: Dict[str, Any]) -> ProfileMap:
    out: ProfileMap = {}
    for slot in SLOT_KEYS:
        val = prod.get(slot)
        if isinstance(val, str) and val.strip():
            out[slot] = val.strip()
    return out


def to_panel_entry(prod_or_profile: Dict[str, Any]) -> ProfileMap:
    """Flat i1..i5 map for wg-easy signatures.json (partial slots allowed)."""
    if "profile_id" in prod_or_profile and any(k in prod_or_profile for k in SLOT_KEYS):
        return prod_to_profile_map(prod_or_profile)
    return prod_to_profile_map(export_prod_profile(prod_or_profile, profile_id=""))


def read_signatures_file(path: Path) -> PanelMap:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"expected JSON object: {path}")
    if "profiles" in raw and isinstance(raw["profiles"], dict):
        raw = raw["profiles"]
    out: PanelMap = {}
    for pid, payload in raw.items():
        if pid.startswith("_") or not isinstance(pid, str):
            continue
        if isinstance(payload, dict):
            entry = to_panel_entry(payload)
            if entry:
                if isinstance(payload.get("_meta"), dict):
                    entry["_meta"] = payload["_meta"]
                out[pid] = entry
    return out


def write_panel_file(path: Path, data: PanelMap) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def merge_profile_into_panel(
    path: Path,
    profile_id: str,
    entry: ProfileMap,
    *,
    meta: Dict[str, Any] | None = None,
) -> PanelMap:
    data: PanelMap = {}
    if path.is_file():
        data = read_signatures_file(path)
    combined: ProfileMap = dict(entry)
    if meta:
        combined["_meta"] = meta
    data[profile_id] = combined
    write_panel_file(path, data)
    return data


def lab_batch_to_panel(lab_data: Dict[str, Any]) -> PanelMap:
    profiles = lab_data.get("profiles") if isinstance(lab_data.get("profiles"), dict) else lab_data
    out: PanelMap = {}
    for pid, payload in profiles.items():
        if not isinstance(pid, str) or pid.startswith("_"):
            continue
        if isinstance(payload, dict):
            entry = to_panel_entry(payload)
            if entry.get("i1"):
                out[pid] = entry
    return out


def prod_to_conf_lines(prod: Dict[str, Any]) -> str:
    lines = export_for_panel(prod_to_profile_map(prod))
    return "\n".join(lines) + ("\n" if lines else "")
