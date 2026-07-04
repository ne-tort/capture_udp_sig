#!/usr/bin/env python3
"""Audit I1-I5 capture pipeline (signature-lab) with strict merge support."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_LAB_ROOT = Path(__file__).resolve().parent
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

from python_signatures.architect_fallbacks import (  # noqa: E402
    ARCHITECT_BUNDLE_DATE,
    ARCHITECT_BUNDLE_VERSION,
)
from python_signatures.base import CollectorOptions  # noqa: E402
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.profile_cps import merge_collector_output_strict  # noqa: E402
from python_signatures.provenance import (  # noqa: E402
    COLLECTOR_KIND,
    SLOT_KEYS,
    CAPTURE_KEYS,
    compare_with_architect,
    validate_cps,
)
from python_signatures.run_all import PROTOCOL_REGISTRY  # noqa: E402
from python_signatures.slot_policy import get_slot_policy  # noqa: E402

logger = logging.getLogger("audit_capture")

CAPTURE_CAPABLE = {
    "quic": "live pcap (browser_capture + tcpdump); dry-run -> fixture",
    "quic_browser": "live pcap (Chromium QUIC chain); dry-run -> fixture",
    "stun": "live pcap (WebRTC STUN out, optional in); dry-run -> fixture",
    "webrtc": "live pcap (WebRTC STUN); dry-run -> fixture",
    "stun_browser": "live pcap (browser STUN); dry-run -> fixture",
    "dns": "template + optional live dig capture",
    "sip": "template hex from profile_templates/sip.json",
    "dtls": "template hex from profile_templates/dtls.json",
}


@dataclass
class ProfileAudit:
    profile_id: str
    collector_kind: str
    capture_capability: str
    dry_run: bool
    allow_architect_fallback: bool
    ok: bool
    error: Optional[str] = None
    capture_raw: Dict[str, Any] = field(default_factory=dict)
    merged: Dict[str, Any] = field(default_factory=dict)
    slot_sources: Dict[str, str] = field(default_factory=dict)
    incomplete_slots: List[str] = field(default_factory=list)
    cps_issues: List[Dict[str, Any]] = field(default_factory=list)
    architect_diff: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _run_collector(profile_id: str, config_dir: Path, timeout: int, dry_run: bool) -> Dict[str, Any]:
    entry = next((e for e in PROTOCOL_REGISTRY if e[0] == profile_id), None)
    if not entry:
        raise ValueError(f"unknown profile: {profile_id}")
    _, collector_cls, config_rel = entry
    config_path = config_dir / config_rel
    opts = CollectorOptions(
        config_path=config_path,
        out_path=None,
        count=1,
        timeout=timeout,
        dry_run=dry_run,
        registry_profile_id=profile_id,
    )
    signatures = collector_cls(opts).collect()
    if not signatures:
        raise RuntimeError("collector returned empty list")
    sig = signatures[0]
    if not isinstance(sig.get("hex"), str):
        raise RuntimeError("collector returned no valid hex (I1)")
    return sig


def audit_profile(
    profile_id: str,
    *,
    config_dir: Path,
    policy_path: Optional[Path],
    timeout: int,
    dry_run: bool,
    allow_architect_fallback: bool,
    strict: bool,
) -> ProfileAudit:
    kind = COLLECTOR_KIND.get(profile_id, "unknown")
    policy = get_slot_policy(profile_id, policy_path=policy_path)
    result = ProfileAudit(
        profile_id=profile_id,
        collector_kind=kind,
        capture_capability=CAPTURE_CAPABLE.get(profile_id, "?"),
        dry_run=dry_run,
        allow_architect_fallback=allow_architect_fallback,
        ok=False,
    )

    try:
        raw = _run_collector(profile_id, config_dir, timeout, dry_run)
        raw = apply_cps_specs_to_sig(profile_id, raw)
        result.capture_raw = {k: raw[k] for k in CAPTURE_KEYS if k in raw}

        merged = merge_collector_output_strict(
            profile_id,
            raw,
            allow_architect=allow_architect_fallback,
            required_slots=policy.get("required_slots"),
        )
        profile_dict = merged.to_profile_dict()
        result.merged = {k: profile_dict[k] for k in SLOT_KEYS if k in profile_dict}
        result.slot_sources = profile_dict.get("slot_sources", {})
        result.incomplete_slots = profile_dict.get("incomplete_slots", [])

        for slot in SLOT_KEYS:
            val = result.merged.get(slot)
            if val:
                for issue in validate_cps(val, slot=slot):
                    result.cps_issues.append(asdict(issue))

        if allow_architect_fallback:
            result.architect_diff = [asdict(d) for d in compare_with_architect(profile_id, result.merged)]

        architect_used = [s for s, src in result.slot_sources.items() if src == "architect"]
        if architect_used and not allow_architect_fallback:
            result.warnings.append(f"architect slots without flag: {architect_used}")

        if result.incomplete_slots:
            result.warnings.append(f"incomplete: {result.incomplete_slots}")

        if dry_run and kind not in ("template", "dns_live"):
            result.warnings.append("DRY-RUN: browser profiles use fixtures")

        err_issues = [i for i in result.cps_issues if i.get("severity") == "error"]
        strict_fail = strict and bool(result.incomplete_slots)
        architect_fail = strict and not allow_architect_fallback and any(
            src == "architect" for src in result.slot_sources.values()
        )
        result.ok = not err_issues and not strict_fail and not architect_fail
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        logger.debug(traceback.format_exc())

    return result


def audit_all(
    *,
    config_dir: Path,
    policy_path: Optional[Path],
    timeout: int,
    dry_run: bool,
    allow_architect_fallback: bool,
    strict: bool,
    profiles: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ids = profiles or [p for p, _, _ in PROTOCOL_REGISTRY]
    audits = [
        audit_profile(
            pid,
            config_dir=config_dir,
            policy_path=policy_path,
            timeout=timeout,
            dry_run=dry_run,
            allow_architect_fallback=allow_architect_fallback,
            strict=strict,
        )
        for pid in ids
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "strict": strict,
        "allow_architect_fallback": allow_architect_fallback,
        "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
        "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
        "profiles_total": len(audits),
        "profiles_ok": sum(1 for a in audits if a.ok),
        "profiles_failed": sum(1 for a in audits if not a.ok),
        "profiles": [asdict(a) for a in audits],
    }


def _print_human(report: Dict[str, Any]) -> None:
    print(
        f"\n=== Audit  dry_run={report['dry_run']}  strict={report['strict']}  "
        f"architect={report['allow_architect_fallback']} ===\n"
    )
    for p in report["profiles"]:
        status = "OK" if p["ok"] else "FAIL"
        print(f"[{status}] {p['profile_id']}  ({p['collector_kind']})")
        if p.get("error"):
            print(f"  ERROR: {p['error']}")
            continue
        for slot in SLOT_KEYS:
            src = p["slot_sources"].get(slot, "?")
            val = p["merged"].get(slot, "")
            preview = (val[:60] + "...") if len(val) > 60 else val
            print(f"  {slot.upper()}: {src}  {preview}")
        if p.get("incomplete_slots"):
            print(f"  incomplete: {p['incomplete_slots']}")
        for w in p.get("warnings", []):
            print(f"  WARN: {w}")
        print()
    print(f"Total: {report['profiles_ok']}/{report['profiles_total']} OK\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit I1-I5 capture (signature-lab)")
    parser.add_argument("--config-dir", type=Path, default=_LAB_ROOT / "python_signatures" / "config")
    parser.add_argument("--policy", type=Path, default=_LAB_ROOT / "capture_policy.yaml")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-architect-fallback", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Fail if incomplete or architect without flag")
    parser.add_argument("--profile", action="append")
    parser.add_argument("--out", type=Path, default=_LAB_ROOT / "output" / "audit_report.json")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    report = audit_all(
        config_dir=args.config_dir.resolve(),
        policy_path=args.policy.resolve() if args.policy else None,
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_architect_fallback=args.allow_architect_fallback,
        strict=args.strict,
        profiles=args.profile,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_human(report)
    return 0 if report["profiles_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
