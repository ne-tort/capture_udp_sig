#!/usr/bin/env python3
"""Seed template_pool from tests/fixtures (bootstrap before live pool build)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

_LAB = Path(__file__).resolve().parent.parent
FIX = _LAB / "tests" / "fixtures" / "signatures"
POOL = _LAB / "python_signatures" / "config" / "template_pool"


def main() -> int:
    copies = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    if not FIX.is_dir():
        print(f"missing {FIX}", file=sys.stderr)
        return 1
    for src in sorted(FIX.glob("*.json")):
        pid = src.stem
        dest_dir = POOL / pid
        dest_dir.mkdir(parents=True, exist_ok=True)
        for i in range(1, copies + 1):
            dst = dest_dir / f"capture_{i:03d}.json"
            if dst.is_file():
                continue
            shutil.copy2(src, dst)
        print(f"{pid}: {len(list(dest_dir.glob('*.json')))} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
