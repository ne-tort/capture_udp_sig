"""
Unified signature bank: one JSON file, per-profile numbered iterations (no dates).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from python_signatures.provenance import SLOT_KEYS

BANK_VERSION = 1

RateLimitInfo = tuple[bool, int]


def empty_bank(*, target: int = 1000) -> Dict[str, Any]:
    return {"version": BANK_VERSION, "target": target, "profiles": {}}


def _normalize_iteration_key(key: Any) -> Optional[int]:
    try:
        n = int(key)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def load_bank(path: Path, *, default_target: int = 1000) -> Dict[str, Any]:
    if not path.is_file():
        return empty_bank(target=default_target)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"signature bank must be a JSON object: {path}")
    if "profiles" not in data or not isinstance(data["profiles"], dict):
        data["profiles"] = {}
    data.setdefault("version", BANK_VERSION)
    if not isinstance(data.get("target"), int) or data["target"] <= 0:
        data["target"] = default_target
    return data


def save_bank(path: Path, bank: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(bank, ensure_ascii=False, indent=2)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def profile_iterations(bank: Dict[str, Any], profile_id: str) -> Dict[int, Dict[str, str]]:
    raw = bank.get("profiles", {}).get(profile_id, {})
    if not isinstance(raw, dict):
        return {}
    out: Dict[int, Dict[str, str]] = {}
    for key, entry in raw.items():
        n = _normalize_iteration_key(key)
        if n is None or not isinstance(entry, dict):
            continue
        slots = entry_from_prod(entry)
        if slots.get("i1"):
            out[n] = slots
    return out


def profile_count(bank: Dict[str, Any], profile_id: str) -> int:
    return len(profile_iterations(bank, profile_id))


def next_iteration(bank: Dict[str, Any], profile_id: str) -> int:
    iters = profile_iterations(bank, profile_id)
    return (max(iters) + 1) if iters else 1


def bank_target(bank: Dict[str, Any]) -> int:
    t = bank.get("target")
    return t if isinstance(t, int) and t > 0 else 1000


def entry_from_prod(prod: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(prod.get("hex"), str) and prod["hex"].strip():
        out["i1"] = prod["hex"].strip()
    for slot in SLOT_KEYS:
        val = prod.get(slot)
        if isinstance(val, str) and val.strip():
            out[slot] = val.strip()
    return out


def append_entry(
    bank: Dict[str, Any],
    profile_id: str,
    iteration: int,
    slots: Dict[str, str],
) -> None:
    profiles = bank.setdefault("profiles", {})
    bucket = profiles.setdefault(profile_id, {})
    bucket[str(iteration)] = {k: slots[k] for k in SLOT_KEYS if slots.get(k)}


def existing_i1_set(bank: Dict[str, Any], profile_id: str) -> Set[str]:
    return {e["i1"] for e in profile_iterations(bank, profile_id).values() if e.get("i1")}


def is_duplicate_i1(bank: Dict[str, Any], profile_id: str, slots: Dict[str, str]) -> bool:
    i1 = slots.get("i1")
    return bool(i1 and i1 in existing_i1_set(bank, profile_id))


_RATE_LIMIT_RE = re.compile(
    r"429|too\s+many\s+requests|rate\s*limit|rate_limit|throttl",
    re.IGNORECASE,
)


def parse_rate_limit_wait(error: str, *, attempt: int, base_sec: int = 15, cap_sec: int = 300) -> RateLimitInfo:
    text = (error or "").strip()
    retry_after = re.search(r"retry[- ]?after[:\s]+(\d+)", text, re.IGNORECASE)
    if not text:
        return False, 0
    is_rl = bool(_RATE_LIMIT_RE.search(text) or retry_after)
    if not is_rl:
        return False, 0
    wait = min(cap_sec, base_sec * (2 ** min(attempt - 1, 5)))
    if retry_after:
        wait = max(wait, int(retry_after.group(1)))
    return True, wait


def is_rate_limited(error: str) -> bool:
    is_rl, _ = parse_rate_limit_wait(error, attempt=1)
    return is_rl


def set_profile_status(
    bank: Dict[str, Any],
    profile_id: str,
    *,
    status: str,
    note: str,
    effective_target: Optional[int] = None,
) -> None:
    meta = bank.setdefault("profile_status", {})
    entry: Dict[str, Any] = {"status": status, "note": note}
    if effective_target is not None:
        entry["effective_target"] = effective_target
    meta[profile_id] = entry


def get_profile_status(bank: Dict[str, Any], profile_id: str) -> Optional[Dict[str, Any]]:
    raw = bank.get("profile_status", {})
    if isinstance(raw, dict):
        st = raw.get(profile_id)
        if isinstance(st, dict):
            return st
    return None


def is_transient_error(error: str) -> bool:
    if is_rate_limited(error):
        return False
    text = (error or "").lower()
    markers = (
        "timeout",
        "timed out",
        "no packets",
        "try again",
        "connection reset",
        "temporarily unavailable",
        "eof",
    )
    return any(m in text for m in markers)


def slots_label(slots: Dict[str, str]) -> str:
    return ",".join(k for k in SLOT_KEYS if slots.get(k))
