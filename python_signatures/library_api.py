"""
Library API for web-panel integration.

Stable programmatic contract for wg-easy and external tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_signatures.architect_fallbacks import ARCHITECT_BUNDLE_DATE, ARCHITECT_BUNDLE_VERSION
from python_signatures.capture_service import capture_profile_live
from python_signatures.export_formats import (
    lab_batch_to_panel,
    merge_profile_into_panel,
    read_signatures_file,
    to_panel_entry,
    write_panel_file,
)
from python_signatures.features import (
    browser_capture_available,
    profile_available,
    unavailable_reason,
)
from python_signatures.run_all import PROTOCOL_REGISTRY, run_all

ProfileMap = Dict[str, str]
ProfilesMap = Dict[str, ProfileMap]


def known_profile_ids(*, available_only: bool = False, dry_run: bool = False) -> list[str]:
    ids = [profile_id for profile_id, _, _ in PROTOCOL_REGISTRY]
    if not available_only:
        return ids
    return [p for p in ids if profile_available(p, dry_run=dry_run)]


def list_profiles_meta(*, dry_run: bool = False) -> Dict[str, Any]:
    items = []
    for pid, _, _ in PROTOCOL_REGISTRY:
        items.append({
            "profile_id": pid,
            "available": profile_available(pid, dry_run=dry_run),
            "unavailable_reason": unavailable_reason(pid),
        })
    return {
        "profile_ids": known_profile_ids(available_only=True, dry_run=dry_run),
        "all_profile_ids": known_profile_ids(),
        "default_profile": known_profile_ids(available_only=True, dry_run=dry_run)[0]
        if known_profile_ids(available_only=True, dry_run=dry_run)
        else "dns",
        "browser_enabled": browser_capture_available(),
        "profiles": items,
    }


def _normalize_profile_entry(raw: Any) -> ProfileMap:
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("{"):
            try:
                raw = json.loads(s)
            except json.JSONDecodeError:
                raw = {"i1": s}
        elif s:
            raw = {"i1": s}
        else:
            raw = {}

    if not isinstance(raw, dict):
        return {}

    out: ProfileMap = {}
    for key in ("i1", "i2", "i3", "i4", "i5"):
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            out[key] = v.strip()
    return out


def _read_profiles(signatures_path: Path) -> ProfilesMap:
    return read_signatures_file(signatures_path)


def get_profile(
    profile_id: str,
    *,
    signatures_path: str | Path,
    require_full: bool = False,
) -> Dict[str, Any]:
    pid = str(profile_id).strip()
    if pid not in known_profile_ids():
        raise ValueError(f"unknown profile_id={pid!r}")

    path = Path(signatures_path).resolve()
    profiles = _read_profiles(path)
    profile = profiles.get(pid)
    if not profile:
        raise ValueError(f"profile {pid!r} not found in signatures file: {path}")
    if not profile.get("i1"):
        raise ValueError(f"profile {pid!r} has no I1 in {path}")
    if require_full:
        missing = [k for k in ("i1", "i2", "i3", "i4", "i5") if not profile.get(k)]
        if missing:
            raise ValueError(f"profile {pid!r} incomplete, missing: {', '.join(missing)}")

    out: Dict[str, Any] = {"profile_id": pid, "source_meta": {
        "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
        "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
        "source": "signatures_json",
        "signatures_path": str(path),
    }}
    for slot in ("i1", "i2", "i3", "i4", "i5"):
        if profile.get(slot):
            out[slot] = profile[slot]
    return out


def get_all_profiles(*, signatures_path: str | Path, require_full: bool = False) -> Dict[str, Dict[str, Any]]:
    path = Path(signatures_path).resolve()
    result: Dict[str, Dict[str, Any]] = {}
    for pid in known_profile_ids(available_only=True):
        try:
            prof = _read_profiles(path).get(pid)
            if prof and prof.get("i1"):
                result[pid] = get_profile(pid, signatures_path=path, require_full=require_full)
        except ValueError:
            continue
    return result


def capture_profile(
    profile_id: str,
    *,
    out_path: Optional[str | Path] = None,
    signatures_path: Optional[str | Path] = None,
    merge_into_signatures: bool = False,
    timeout: Optional[int] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Capture one profile; optionally merge into panel signatures.json."""
    res = capture_profile_live(profile_id, timeout=timeout, dry_run=dry_run)
    if not res.ok:
        return {"success": False, "profile_id": profile_id, "error": res.error}

    entry = to_panel_entry(res.prod)
    if merge_into_signatures and signatures_path:
        merge_profile_into_panel(Path(signatures_path), profile_id, entry)
    if out_path:
        Path(out_path).write_text(json.dumps(res.prod, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "success": True,
        "profile_id": profile_id,
        "slots": sorted(entry.keys()),
        "prod": res.prod,
        "out_path": str(out_path) if out_path else None,
        "merged_into": str(signatures_path) if merge_into_signatures and signatures_path else None,
    }


def regenerate_signatures(
    *,
    out_path: str | Path,
    config_dir: str | Path,
    timeout: int = 30,
    dry_run: bool = False,
    panel_format: bool = True,
    available_only: bool = True,
) -> Dict[str, Any]:
    """Regenerate signatures; default panel flat JSON with only available profiles."""
    out_p = Path(out_path).resolve()
    cfg_p = Path(config_dir).resolve()
    data = run_all(
        cfg_p,
        out_p,
        timeout=timeout,
        dry_run=dry_run,
        available_only=available_only,
        skip_errors=True,
    )
    if panel_format:
        panel = lab_batch_to_panel(data)
        write_panel_file(out_p, panel)
        count = len(panel)
    else:
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        count = len(data.get("profiles", {}))

    return {
        "success": True,
        "profiles_count": count,
        "out_path": str(out_p),
        "dry_run": bool(dry_run),
        "panel_format": panel_format,
        "skipped_profiles": data.get("_meta", {}).get("skipped_profiles", []),
        "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
        "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
    }


def invoke(action: str, **kwargs: Any) -> Any:
    """JSON-friendly dispatch for Node child_process (`python -c library_api.invoke(...)`)."""
    table = {
        "known_profile_ids": lambda: known_profile_ids(**kwargs),
        "list_profiles_meta": lambda: list_profiles_meta(**kwargs),
        "get_profile": lambda: get_profile(**kwargs),
        "capture_profile": lambda: capture_profile(**kwargs),
        "regenerate_signatures": lambda: regenerate_signatures(**kwargs),
    }
    if action not in table:
        raise ValueError(f"unknown action: {action}")
    return table[action]()
