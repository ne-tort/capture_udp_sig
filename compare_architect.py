#!/usr/bin/env python3
"""Side-by-side compare capture merge vs Architect fallback (signature-lab)."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

_LAB_ROOT = Path(__file__).resolve().parent
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

from python_signatures.base import CollectorOptions
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.profile_cps import merge_collector_output_strict
from python_signatures.provenance import SLOT_KEYS, compare_with_architect
from python_signatures.run_all import PROTOCOL_REGISTRY

COLLECTOR_MAP = {pid: (cls, rel) for pid, cls, rel in PROTOCOL_REGISTRY}


def compare_profile(
    profile_id: str,
    *,
    config_dir: Path,
    timeout: int,
    dry_run: bool,
) -> Dict[str, Any]:
    if profile_id not in COLLECTOR_MAP:
        raise ValueError(f"unknown profile: {profile_id}")

    cls, rel = COLLECTOR_MAP[profile_id]
    opts = CollectorOptions(
        config_path=config_dir / rel,
        timeout=timeout,
        dry_run=dry_run,
        registry_profile_id=profile_id,
    )
    sig = apply_cps_specs_to_sig(profile_id, cls(opts).collect()[0])

    strict = merge_collector_output_strict(profile_id, sig, allow_architect=False)
    with_arch = merge_collector_output_strict(profile_id, sig, allow_architect=True)

    diffs = compare_with_architect(profile_id, strict.to_legacy_dict())

    return {
        "profile_id": profile_id,
        "capture_only": strict.to_profile_dict(),
        "with_architect": with_arch.to_profile_dict(),
        "architect_comparison": [asdict(d) for d in diffs],
        "slots_filled_capture": [s for s in SLOT_KEYS if getattr(strict, s) or (s == "i1" and strict.i1)],
        "slots_filled_architect": [
            s for s in SLOT_KEYS if (getattr(with_arch, s) if s != "i1" else with_arch.i1)
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compare capture vs Architect per profile")
    parser.add_argument("--profile", required=True, action="append")
    parser.add_argument("--config-dir", type=Path, default=_LAB_ROOT / "python_signatures" / "config")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", type=Path, default=_LAB_ROOT / "output" / "architect_compare.json")
    args = parser.parse_args(argv)

    results: List[Dict[str, Any]] = []
    for pid in args.profile:
        results.append(
            compare_profile(
                pid,
                config_dir=args.config_dir.resolve(),
                timeout=args.timeout,
                dry_run=args.dry_run,
            )
        )

    report = {"profiles": results}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    for r in results:
        print(f"\n=== {r['profile_id']} ===")
        print(f"  capture slots: {r['slots_filled_capture']}")
        print(f"  +architect slots: {r['slots_filled_architect']}")
        for d in r["architect_comparison"]:
            if not d["same"] and d["capture_value"]:
                print(f"  diff {d['slot']}: {d['structural_note']}")

    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
