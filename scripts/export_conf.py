#!/usr/bin/env python3
"""Export merged profile to .conf I-lines (signature-lab)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LAB_ROOT = Path(__file__).resolve().parent.parent
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

from python_signatures.provenance import export_for_panel, SLOT_KEYS


def main() -> int:
    parser = argparse.ArgumentParser(description="Export I1-I5 lines from signatures JSON")
    parser.add_argument("--in", dest="in_path", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()

    data = json.loads(args.in_path.read_text(encoding="utf-8"))
    profiles = data.get("profiles", data)
    prof = profiles.get(args.profile)
    if not prof:
        raise SystemExit(f"profile not found: {args.profile}")

    for line in export_for_panel(prof):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
