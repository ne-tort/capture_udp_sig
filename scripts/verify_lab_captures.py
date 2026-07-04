#!/usr/bin/env python3
"""Verify all live captures + cross-profile mode analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

_LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_LAB))

from python_signatures.provenance import SLOT_KEYS
from python_signatures.protocol_verify import verify_profile_slots
from python_signatures.quic_verify import parse_pure_b_tag


def _slots_from_prod(data: dict) -> List[str]:
    return [s for s in SLOT_KEYS if s in data]


def _slots_from_debug(path: Path) -> dict:
    if not path.is_file():
        return {"exists": False}
    d = json.loads(path.read_text(encoding="utf-8"))
    captured = d.get("captured_slots") or _slots_from_prod(d.get("prod", d))
    return {
        "exists": True,
        "captured_slots": captured,
        "missing_optional": d.get("missing_optional", []),
        "timeout_sec": d.get("timeout_sec"),
        "target": (d.get("profile") or {}).get("_capture_meta", {}).get("target"),
    }


def _payload_fingerprint(cps: str) -> str | None:
    raw = parse_pure_b_tag(cps)
    if raw is None:
        # hybrid CPS: hash first 16 bytes of static part
        if cps.lower().startswith("<b 0x"):
            hx = cps[5 : cps.find(">")].strip()[:32]
            return f"hybrid:{hx}"
        return None
    return raw[:16].hex()


def compare_quic_profiles(prods: Dict[str, dict]) -> dict:
    """Compare quic vs quic_browser I-slot fingerprints."""
    out: dict = {}
    for slot in SLOT_KEYS:
        fps = {}
        for pid in ("quic", "quic_browser"):
            if pid not in prods:
                continue
            fp = _payload_fingerprint(prods[pid].get(slot, ""))
            if fp:
                fps[pid] = fp
        if len(fps) == 2:
            out[slot] = {"same_prefix": fps["quic"] == fps["quic_browser"], **fps}
    return out


def analyze_partial(profile_id: str, info: dict, policy: dict) -> dict:
    max_slots = policy.get("max_slots", 5)
    captured = info.get("captured_slots", [])
    expected_max = min(5, max_slots)
    notes = policy.get("notes", "")

    if len(captured) >= 5:
        status = "full_i5"
    elif len(captured) >= expected_max:
        status = "max_for_mode"
    elif len(captured) >= 1:
        status = "partial_ok"
    else:
        status = "empty"

    return {
        "status": status,
        "captured": captured,
        "count": len(captured),
        "max_slots_policy": max_slots,
        "notes": notes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=_LAB / "output")
    parser.add_argument("--out", type=Path, default=_LAB / "output" / "verification_report.json")
    args = parser.parse_args()

    import yaml
    from python_signatures.slot_policy import get_slot_policy

    modes_path = _LAB / "protocol_modes.yaml"
    modes = yaml.safe_load(modes_path.read_text()) if modes_path.is_file() else {}

    report: Dict[str, Any] = {"profiles": {}, "quic_compare": {}, "summary": {}}
    prods: Dict[str, dict] = {}

    for prod_path in sorted(args.output_dir.glob("live_*.json")):
        if prod_path.name.endswith("_debug.json"):
            continue
        profile_id = prod_path.stem.replace("live_", "")
        prod = json.loads(prod_path.read_text(encoding="utf-8"))
        prods[profile_id] = prod
        debug_path = prod_path.with_name(f"{prod_path.stem}_debug.json")
        debug_data = json.loads(debug_path.read_text(encoding="utf-8")) if debug_path.is_file() else {}

        raw_for_verify = {k: prod[k] for k in SLOT_KEYS if k in prod}
        if debug_data.get("verification"):
            ver_list = debug_data["verification"]
        else:
            reports = verify_profile_slots(profile_id, raw_for_verify)
            ver_list = [
                {
                    "slot": r.slot,
                    "ok": r.ok,
                    "byte_len": getattr(r, "byte_len", 0),
                    "issues": getattr(r, "issues", []),
                    "warnings": getattr(r, "warnings", []),
                }
                for r in reports
            ]

        info = _slots_from_debug(debug_path)
        policy = get_slot_policy(profile_id)

        report["profiles"][profile_id] = {
            "prod_slots": _slots_from_prod(prod),
            "verification": ver_list,
            "capture_info": info,
            "partial_analysis": analyze_partial(profile_id, info, policy),
            "mode": (modes.get("modes") or {}).get(profile_id, {}),
        }

    if "quic" in prods and "quic_browser" in prods:
        report["quic_compare"] = compare_quic_profiles(prods)

    full = [p for p, d in report["profiles"].items() if len(d.get("prod_slots", [])) >= 5]
    partial = [p for p, d in report["profiles"].items() if 0 < len(d.get("prod_slots", [])) < 5]
    report["summary"] = {
        "full_i5": full,
        "partial": partial,
        "verified_ok": [
            p for p, d in report["profiles"].items()
            if all(v.get("ok", v.get("issues") == []) for v in d.get("verification", []) if v.get("slot") == "i1")
        ],
    }
    report["mode_splits"] = {
        "quic_family": ["quic", "quic_browser", "quic_tls_browser"],
        "stun_family": ["webrtc", "stun", "stun_browser"],
        "sip_family": ["sip", "sip_multi"],
        "rationale": {
            "sip vs sip_multi": "1 OPTIONS (I1-I2) vs 3 client OPTIONS rounds (up to I5); different signatures",
            "quic_tls_browser": "I1 is TCP TLS ClientHello, not QUIC — separate signature shape",
            "webrtc vs stun/stun_browser": "use_response=false → 1 slot; with response → 2 slots (policy max)",
            "stun vs stun_browser": "same capture; stun_browser applies CPS hybrid for prod",
        },
    }
    report["udp_extensions"] = {
        "implemented": ["ntp"],
        "browser_feasible": ["quic_tls_browser"],
        "deferred": {
            "turn_browser": "needs TURN credentials + WebRTC trigger extension",
            "mdns": "multicast blocked in Docker bridge",
            "wireguard": "needs real WG handshake / keys",
            "doq": "no stable public DoQ in browser without custom client",
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Report -> {args.out}")
    print(f"Full I5: {full}")
    print(f"Partial: {partial}")
    if report["quic_compare"]:
        same = [s for s, v in report["quic_compare"].items() if v.get("same_prefix")]
        print(f"QUIC same-prefix slots: {same or 'none'} (expected: none — different targets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
