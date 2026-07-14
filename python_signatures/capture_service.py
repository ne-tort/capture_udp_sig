"""
Single-profile live capture pipeline (shared by CLI, library_api, Docker).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from python_signatures.base import CollectorOptions
from python_signatures.capture_timeouts import get_capture_timeout
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.features import profile_available, unavailable_reason
from python_signatures.profile_cps import merge_collector_output_strict
from python_signatures.provenance import SLOT_KEYS, export_prod_profile
from python_signatures.protocol_verify import reports_to_dicts, verify_profile_slots
from python_signatures.run_all import PROTOCOL_REGISTRY


@dataclass
class CaptureResult:
    ok: bool
    profile_id: str
    prod: Dict[str, Any] = field(default_factory=dict)
    profile: Dict[str, Any] = field(default_factory=dict)
    verification: List[Dict[str, Any]] = field(default_factory=list)
    captured_slots: List[str] = field(default_factory=list)
    missing_optional: List[str] = field(default_factory=list)
    dropped_invalid: List[str] = field(default_factory=list)
    timeout_sec: int = 0
    error: Optional[str] = None

    def to_debug_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "profile_id": self.profile_id,
            "timeout_sec": self.timeout_sec,
            "prod": self.prod,
            "profile": self.profile,
            "verification": self.verification,
            "captured_slots": self.captured_slots,
            "missing_optional": self.missing_optional,
            "dropped_invalid": self.dropped_invalid,
            "error": self.error,
        }


def _collector_for(profile_id: str):
    entry = next((e for e in PROTOCOL_REGISTRY if e[0] == profile_id), None)
    if not entry:
        raise ValueError(f"unknown profile: {profile_id}")
    return entry


def _raw_slots_present(raw: dict) -> Set[str]:
    present: Set[str] = set()
    if isinstance(raw.get("hex"), str) and raw["hex"].strip():
        present.add("i1")
    for slot in ("i2", "i3", "i4", "i5"):
        if isinstance(raw.get(slot), str) and raw[slot].strip():
            present.add(slot)
    return present


def _raw_profile_for_verify(raw: dict) -> dict:
    out = {slot: raw[slot] for slot in ("i2", "i3", "i4", "i5") if slot in raw}
    if raw.get("hex"):
        out["i1"] = raw["hex"]
    return out


def _strip_failed_optional(profile: dict, reports: List[Any], required: List[str]) -> List[str]:
    dropped: List[str] = []
    for rep in reports:
        slot = rep.slot if hasattr(rep, "slot") else rep.get("slot")
        ok = rep.ok if hasattr(rep, "ok") else not rep.get("issues")
        if slot in required:
            continue
        if not ok:
            profile.pop(slot, None)
            src = profile.get("slot_sources", {})
            if isinstance(src, dict):
                src[slot] = "invalid"
            dropped.append(slot)
    return dropped


def capture_profile_live(
    profile_id: str,
    *,
    config_dir: Optional[Path] = None,
    timeout: Optional[int] = None,
    dry_run: bool = False,
) -> CaptureResult:
    """Run one profile collector + verify + strict merge → prod dict."""
    pid = str(profile_id).strip()
    if not dry_run and not profile_available(pid, dry_run=dry_run):
        reason = unavailable_reason(pid) or "profile unavailable"
        return CaptureResult(ok=False, profile_id=pid, error=reason)

    profile_id, collector_cls, config_rel = _collector_for(pid)
    lab_root = Path(__file__).resolve().parent.parent
    tmo = get_capture_timeout(profile_id, override=timeout)

    if not dry_run:
        import os
        from python_signatures.capture_docker import (
            capture_docker_enabled,
            capture_via_docker,
            run_profile_capture_docker,
        )

        in_capture_image = os.environ.get("CAPTURE_IN_DOCKER") == "1"
        if not in_capture_image and capture_docker_enabled() and capture_via_docker():
            dr = run_profile_capture_docker(profile_id, lab_root=lab_root, timeout=tmo)
            if not dr.get("ok"):
                return CaptureResult(ok=False, profile_id=profile_id, timeout_sec=tmo, error=dr.get("error"))
            prod = dr["prod"]
            from python_signatures.export_formats import to_panel_entry
            entry = to_panel_entry(prod)
            return CaptureResult(
                ok=True,
                profile_id=profile_id,
                prod={**prod, "ok": True},
                captured_slots=sorted(entry.keys()),
                timeout_sec=tmo,
            )

    cfg_path = (config_dir or Path(__file__).resolve().parent / "config") / config_rel

    from python_signatures.slot_policy import get_slot_policy

    policy = get_slot_policy(profile_id)
    required = policy.get("required_slots") or ["i1"]
    optional = policy.get("optional_slots") or [s for s in SLOT_KEYS if s not in required]

    opts = CollectorOptions(
        config_path=cfg_path,
        timeout=tmo,
        dry_run=dry_run,
        registry_profile_id=profile_id,
    )
    try:
        raw = collector_cls(opts).collect()[0]
    except Exception as e:
        return CaptureResult(ok=False, profile_id=profile_id, timeout_sec=tmo, error=str(e))

    captured = sorted(_raw_slots_present(raw))
    if dry_run:
        if "i1" not in captured:
            return CaptureResult(
                ok=False,
                profile_id=profile_id,
                timeout_sec=tmo,
                captured_slots=captured,
                error="I1 missing (dry-run)",
            )
        reports = []
    else:
        reports = verify_profile_slots(profile_id, _raw_profile_for_verify(raw))
        i1_rep = next((r for r in reports if getattr(r, "slot", None) == "i1"), None)
        if i1_rep is None or not i1_rep.ok:
            return CaptureResult(
                ok=False,
                profile_id=profile_id,
                timeout_sec=tmo,
                verification=reports_to_dicts(reports),
                captured_slots=captured,
                error="I1 missing or invalid",
            )

    sig = apply_cps_specs_to_sig(profile_id, raw)
    # No template/architect fillers — prod JSON is capture-only.
    merged = merge_collector_output_strict(
        profile_id, sig, allow_template_fallback=False, required_slots=required,
    )
    profile = merged.to_profile_dict()
    profile["_capture_meta"] = {
        k: sig[k]
        for k in ("_capture_chain_len", "_bpf", "_outgoing_udp", "target", "_resolver", "_client_rounds", "_client_polls")
        if k in sig
    }

    dropped = _strip_failed_optional(profile, reports, required) if reports else []
    missing_required = [s for s in required if s not in captured]
    if missing_required:
        return CaptureResult(
            ok=False,
            profile_id=profile_id,
            timeout_sec=tmo,
            profile=profile,
            verification=reports_to_dicts(reports),
            captured_slots=captured,
            dropped_invalid=dropped,
            error=f"required slots missing: {missing_required}",
        )

    missing_optional = [s for s in optional if s not in captured]
    prod = export_prod_profile(profile, profile_id=profile_id)
    prod["ok"] = True

    return CaptureResult(
        ok=True,
        profile_id=profile_id,
        prod=prod,
        profile=profile,
        verification=reports_to_dicts(reports),
        captured_slots=captured,
        missing_optional=missing_optional,
        dropped_invalid=dropped,
        timeout_sec=tmo,
    )
