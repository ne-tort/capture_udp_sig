#!/usr/bin/env python3
"""Live capture for any signature-lab profile -> prod JSON + debug JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_LAB))

from python_signatures.capture_service import capture_profile_live
from python_signatures.provenance import SLOT_KEYS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--debug-out", type=Path, default=None)
    args = parser.parse_args()

    res = capture_profile_live(args.profile, timeout=args.timeout)
    print(f"=== {res.profile_id} verification (timeout={res.timeout_sec}s) ===")
    for rep in res.verification:
        status = "OK" if not rep.get("issues") else "FAIL"
        extra = f" {rep.get('byte_len')}B" if rep.get("byte_len") else ""
        print(f"  [{status}] {str(rep.get('slot', '')).upper()}{extra}")

    if not res.ok:
        print(f"FAIL: {res.error}", file=sys.stderr)
        return 1

    for slot in res.missing_optional:
        print(f"WARN: {slot.upper()} not captured (omitted from prod JSON)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(res.prod, ensure_ascii=False, indent=2), encoding="utf-8")
    debug_path = args.debug_out or args.out.with_name(f"{args.out.stem}_debug.json")
    debug_path.write_text(json.dumps(res.to_debug_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    filled = [s for s in SLOT_KEYS if s in res.prod]
    print(f"OK {res.profile_id} prod_slots={filled} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
