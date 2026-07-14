#!/usr/bin/env python3
"""Overwrite signatures.default.json + template_pool from output/live_*.json only."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
DEFAULTS = ROOT / "python_signatures" / "config" / "signatures.default.json"
POOL = ROOT / "python_signatures" / "config" / "template_pool"
SLOTS = ("i1", "i2", "i3", "i4", "i5")
DYN = re.compile(r"<(rc|r|t|c|rd)\b")


def main() -> int:
    defaults: dict[str, dict[str, str]] = {}
    for path in sorted(OUT.glob("live_*.json")):
        if "_debug" in path.name:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        pid = data.get("profile_id") or path.stem.replace("live_", "", 1)
        if data.get("ok") is False:
            print(f"FAIL {pid}: ok=false", file=sys.stderr)
            return 1
        slots = {k: data[k] for k in SLOTS if isinstance(data.get(k), str) and data[k].strip()}
        if not slots.get("i1"):
            print(f"FAIL {pid}: missing i1", file=sys.stderr)
            return 1
        for k, v in slots.items():
            if DYN.search(v):
                print(f"FAIL {pid}.{k}: dynamic CPS tags not allowed: {DYN.findall(v)}", file=sys.stderr)
                return 1
            if not v.strip().lower().startswith("<b 0x"):
                print(f"FAIL {pid}.{k}: must be <b 0x...> snapshot", file=sys.stderr)
                return 1
        defaults[pid] = slots
        print(f"OK {pid}: {list(slots)}")

        dest_dir = POOL / pid
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Keep only capture_001 as the fixed real snapshot; drop other pool junk.
        for old in dest_dir.glob("*.json"):
            old.unlink()
        payload = {"profile_id": pid, **slots}
        (dest_dir / "capture_001.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    if len(defaults) < 11:
        print(f"FAIL: expected 11 profiles, got {len(defaults)}: {sorted(defaults)}", file=sys.stderr)
        return 1

    DEFAULTS.write_text(json.dumps(defaults, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {DEFAULTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
