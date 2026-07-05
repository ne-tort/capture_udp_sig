"""
Pre-captured template pool: random fallback when live capture fails or slots are missing.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_signatures.provenance import SLOT_KEYS, export_prod_profile

_POOL_ROOT = Path(__file__).resolve().parent / "config" / "template_pool"


def pool_dir(profile_id: str) -> Path:
    return _POOL_ROOT / profile_id


def list_pool_entries(profile_id: str) -> List[Dict[str, Any]]:
    d = pool_dir(profile_id)
    if not d.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for path in sorted(d.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                out.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return out


def pool_size(profile_id: str) -> int:
    return len(list_pool_entries(profile_id))


def _normalize_entry(raw: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(raw.get("hex"), str) and raw["hex"].strip():
        out["i1"] = raw["hex"].strip()
    for slot in SLOT_KEYS:
        val = raw.get(slot)
        if isinstance(val, str) and val.strip():
            out[slot] = val.strip()
    return out


def pick_random_entry(profile_id: str) -> Optional[Dict[str, str]]:
    entries = list_pool_entries(profile_id)
    if not entries:
        return None
    return _normalize_entry(random.choice(entries))


def pick_random_panel_entry(profile_id: str) -> Optional[Dict[str, str]]:
    entry = pick_random_entry(profile_id)
    if not entry or not entry.get("i1"):
        return None
    return entry


def fill_missing_from_pool(profile_id: str, partial: Dict[str, str]) -> Dict[str, str]:
    """Merge partial capture with random pool entry for empty slots."""
    out = {k: v for k, v in partial.items() if isinstance(v, str) and v.strip()}
    if all(out.get(s) for s in SLOT_KEYS if s in out) and len(out) >= 5:
        return out
    tpl = pick_random_entry(profile_id)
    if not tpl:
        return out
    for slot in SLOT_KEYS:
        if not out.get(slot) and tpl.get(slot):
            out[slot] = tpl[slot]
    return out


def build_panel_defaults() -> Dict[str, Dict[str, str]]:
    """First pool entry per profile → bundled signatures.default.json."""
    from python_signatures.run_all import PROTOCOL_REGISTRY

    out: Dict[str, Dict[str, str]] = {}
    for pid, _, _ in PROTOCOL_REGISTRY:
        entries = list_pool_entries(pid)
        if not entries:
            continue
        entry = _normalize_entry(entries[0])
        if entry.get("i1"):
            out[pid] = {k: entry[k] for k in SLOT_KEYS if entry.get(k)}
    return out


def save_capture_to_pool(profile_id: str, prod: Dict[str, Any], *, index: Optional[int] = None) -> Path:
    d = pool_dir(profile_id)
    d.mkdir(parents=True, exist_ok=True)
    if index is None:
        index = len(list(d.glob("*.json"))) + 1
    path = d / f"capture_{index:03d}.json"
    payload = {k: prod[k] for k in (*SLOT_KEYS, "profile_id") if prod.get(k)}
    if prod.get("hex"):
        payload["hex"] = prod["hex"]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
