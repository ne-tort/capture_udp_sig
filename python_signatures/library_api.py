"""
Library API for wg-easy panel integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_signatures.capture_service import capture_profile_live
from python_signatures.export_formats import (
    merge_profile_into_panel,
    read_signatures_file,
    to_panel_entry,
    write_panel_file,
)
from python_signatures.features import (
    browser_capture_available,
    live_capture_available,
    profile_available,
    unavailable_reason,
)
from python_signatures.profile_catalog import catalog_entry
from python_signatures.provenance import SLOT_KEYS
from python_signatures.run_all import PROTOCOL_REGISTRY
from python_signatures.template_pool import (
    build_panel_defaults,
    fill_missing_from_pool,
    pick_random_panel_entry,
    pool_size,
    save_capture_to_pool,
)

ProfileMap = Dict[str, str]
ProfilesMap = Dict[str, ProfileMap]


def known_profile_ids(*, available_only: bool = False, dry_run: bool = False) -> list[str]:
    ids = [profile_id for profile_id, _, _ in PROTOCOL_REGISTRY]
    if not available_only:
        return ids
    return [p for p in ids if profile_available(p, dry_run=dry_run)]


def list_profiles_meta(
    *,
    signatures_path: Optional[str | Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    stored: ProfilesMap = {}
    if signatures_path:
        p = Path(signatures_path)
        if p.is_file():
            stored = read_signatures_file(p)

    profiles: List[Dict[str, Any]] = []
    for pid, _, _ in PROTOCOL_REGISTRY:
        cat = catalog_entry(pid)
        in_store = bool(stored.get(pid, {}).get("i1"))
        entry_meta = stored.get(pid, {}).get("_meta") if isinstance(stored.get(pid), dict) else None
        signature_source = entry_meta.get("source") if isinstance(entry_meta, dict) else None
        capturable = profile_available(pid, dry_run=dry_run)
        profiles.append({
            **cat,
            "available": capturable,
            "capturable": capturable,
            "unavailable_reason": unavailable_reason(pid),
            "in_signatures": in_store,
            "signature_source": signature_source,
            "pool_size": pool_size(pid),
            "ready": in_store or pool_size(pid) > 0,
        })

    ready_ids = [p["profile_id"] for p in profiles if p["ready"]]
    default = "dns" if "dns" in ready_ids else (ready_ids[0] if ready_ids else "dns")

    return {
        "profile_ids": [p["profile_id"] for p in profiles],
        "all_profile_ids": [p["profile_id"] for p in profiles],
        "ready_profile_ids": ready_ids,
        "capturable_profile_ids": known_profile_ids(available_only=True, dry_run=dry_run),
        "default_profile": default,
        "browser_enabled": browser_capture_available(),
        "live_capture_available": live_capture_available(),
        "profiles": profiles,
    }


def _capture_meta(source: str, *, error: Optional[str] = None) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "source": source,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    if error:
        meta["capture_error"] = error
    return meta


def _write_capture_status(status_path: Optional[str | Path], payload: Dict[str, Any]) -> None:
    if not status_path:
        return
    p = Path(status_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


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
    for key in SLOT_KEYS:
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            out[key] = v.strip()
    return out


def resolve_profile_entry(
    profile_id: str,
    *,
    signatures_path: str | Path,
) -> tuple[ProfileMap, str]:
    """Return panel entry + source: signatures | template_pool."""
    pid = str(profile_id).strip()
    path = Path(signatures_path).resolve()
    stored = read_signatures_file(path) if path.is_file() else {}
    entry = stored.get(pid)
    if entry and entry.get("i1"):
        return entry, "signatures"
    tpl = pick_random_panel_entry(pid)
    if tpl and tpl.get("i1"):
        return tpl, "template_pool"
    raise ValueError(f"profile {pid!r} not in signatures and template pool is empty")


def get_profile(
    profile_id: str,
    *,
    signatures_path: str | Path,
    require_full: bool = False,
) -> Dict[str, Any]:
    pid = str(profile_id).strip()
    if pid not in known_profile_ids():
        raise ValueError(f"unknown profile_id={pid!r}")

    profile, source = resolve_profile_entry(pid, signatures_path=signatures_path)
    if require_full:
        missing = [k for k in SLOT_KEYS if not profile.get(k)]
        if missing:
            raise ValueError(f"profile {pid!r} incomplete, missing: {', '.join(missing)}")

    out: Dict[str, Any] = {
        "profile_id": pid,
        "source_meta": {
            "source": source,
            "signatures_path": str(Path(signatures_path).resolve()),
        },
    }
    for slot in SLOT_KEYS:
        if profile.get(slot):
            out[slot] = profile[slot]
    return out


def capture_profile(
    profile_id: str,
    *,
    out_path: Optional[str | Path] = None,
    signatures_path: Optional[str | Path] = None,
    merge_into_signatures: bool = False,
    timeout: Optional[int] = None,
    dry_run: bool = False,
    use_template_on_failure: bool = True,
    status_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    pid = str(profile_id).strip()
    source = "capture"
    error: Optional[str] = None

    _write_capture_status(status_path, {
        "state": "running",
        "action": "capture_profile",
        "current_profile": pid,
        "profiles_total": 1,
        "profiles_done": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    res = capture_profile_live(pid, timeout=timeout, dry_run=dry_run)
    if res.ok:
        entry = to_panel_entry(res.prod)
        try:
            save_capture_to_pool(pid, res.prod)
        except OSError:
            pass
    elif use_template_on_failure:
        tpl = pick_random_panel_entry(pid)
        if not tpl:
            err = {"success": False, "profile_id": pid, "error": res.error or "capture failed, pool empty"}
            _write_capture_status(status_path, {"state": "error", "result": err, "finished_at": datetime.now(timezone.utc).isoformat()})
            return err
        entry = fill_missing_from_pool(pid, tpl)
        source = "template_pool"
        error = res.error
    else:
        err = {"success": False, "profile_id": pid, "error": res.error}
        _write_capture_status(status_path, {"state": "error", "result": err, "finished_at": datetime.now(timezone.utc).isoformat()})
        return err

    if merge_into_signatures and signatures_path:
        merge_profile_into_panel(
            Path(signatures_path), pid, entry, meta=_capture_meta(source, error=error),
        )
    if out_path:
        Path(out_path).write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")

    result = {
        "success": True,
        "profile_id": pid,
        "source": source,
        "slots": sorted(entry.keys()),
        "capture_error": error,
        "merged_into": str(signatures_path) if merge_into_signatures and signatures_path else None,
    }
    _write_capture_status(status_path, {
        "state": "done",
        "action": "capture_profile",
        "current_profile": pid,
        "profiles_total": 1,
        "profiles_done": 1,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
    })
    return result


def capture_all_profiles(
    *,
    signatures_path: str | Path,
    timeout: Optional[int] = None,
    dry_run: bool = False,
    only_capturable: bool = True,
    status_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    path = Path(signatures_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        init_signatures_defaults(out_path=path)

    profile_ids = [
        pid for pid in known_profile_ids()
        if not only_capturable or profile_available(pid, dry_run=dry_run)
    ]
    _write_capture_status(status_path, {
        "state": "running",
        "action": "capture_all_profiles",
        "profiles_total": len(profile_ids),
        "profiles_done": 0,
        "current_profile": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    results: List[Dict[str, Any]] = []
    for i, pid in enumerate(profile_ids):
        _write_capture_status(status_path, {
            "state": "running",
            "action": "capture_all_profiles",
            "profiles_total": len(profile_ids),
            "profiles_done": i,
            "current_profile": pid,
            "started_at": datetime.now(timezone.utc).isoformat(),
        })
        results.append(capture_profile(
            pid,
            signatures_path=path,
            merge_into_signatures=True,
            timeout=timeout,
            dry_run=dry_run,
        ))
        _write_capture_status(status_path, {
            "state": "running",
            "action": "capture_all_profiles",
            "profiles_total": len(profile_ids),
            "profiles_done": i + 1,
            "current_profile": pid,
            "last_result": results[-1],
        })

    ok = sum(1 for r in results if r.get("success"))
    live = sum(1 for r in results if r.get("source") == "capture")
    return {
        "success": ok > 0,
        "captured": ok,
        "live_captured": live,
        "total": len(results),
        "results": results,
        "out_path": str(path),
    }


def init_signatures_defaults(*, out_path: str | Path) -> Dict[str, Any]:
    """Write signatures.json from template pool (first entry per profile)."""
    panel = build_panel_defaults()
    if not panel:
        raise RuntimeError("template pool is empty; run scripts/build_template_pool.py")
    write_panel_file(Path(out_path), panel)
    return {"success": True, "profiles_count": len(panel), "out_path": str(out_path)}


def invoke(action: str, **kwargs: Any) -> Any:
    table = {
        "known_profile_ids": lambda: known_profile_ids(**kwargs),
        "list_profiles_meta": lambda: list_profiles_meta(**kwargs),
        "get_profile": lambda: get_profile(**kwargs),
        "resolve_profile_entry": lambda: dict(
            zip(("entry", "source"), resolve_profile_entry(**kwargs))
        ),
        "capture_profile": lambda: capture_profile(**kwargs),
        "capture_all_profiles": lambda: capture_all_profiles(**kwargs),
        "init_signatures_defaults": lambda: init_signatures_defaults(**kwargs),
    }
    if action not in table:
        raise ValueError(f"unknown action: {action}")
    return table[action]()
