#!/usr/bin/env python3
"""Verify QUIC prod/debug JSON from live capture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_LAB))

from python_signatures.quic_verify import print_verification_report, verify_quic_slots


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify QUIC I-slots in capture JSON")
    parser.add_argument("--in", dest="in_path", type=Path, required=True)
    args = parser.parse_args()

    data = json.loads(args.in_path.read_text(encoding="utf-8"))
    if "profile" in data:
        profile = data["profile"]
    else:
        profile = {k: data[k] for k in ("i1", "i2", "i3", "i4", "i5") if k in data}

    reports = verify_quic_slots(profile)
    print_verification_report(reports)
    return 0 if all(r.ok for r in reports if r.slot == "i1") else 1


if __name__ == "__main__":
    sys.exit(main())
