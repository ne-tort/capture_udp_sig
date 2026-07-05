#!/usr/bin/env python3
"""Build template_pool from repeated live captures (Docker recommended)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_LAB))

from python_signatures.run_all import PROTOCOL_REGISTRY
from python_signatures.template_pool import pool_size, save_capture_to_pool


def _docker_capture(profile_id: str, timeout: int) -> dict | None:
    out_dir = _LAB / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    prod_path = out_dir / f"live_{profile_id}.json"
    if prod_path.is_file():
        prod_path.unlink()

    cmd = [
        "docker", "run", "--rm",
        "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
        "-v", f"{out_dir}:/lab/output",
        "capture-udp-sig",
        profile_id,
        str(timeout),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return None
    if not prod_path.is_file():
        return None
    return json.loads(prod_path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--profile", action="append", default=None)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    profiles = args.profile or [p[0] for p in PROTOCOL_REGISTRY]

    if args.docker:
        print("=== docker build capture-udp-sig ===")
        subprocess.run(
            ["docker", "build", "-f", "Dockerfile.capture", "-t", "capture-udp-sig", str(_LAB)],
            check=True,
        )

    for pid in profiles:
        before = pool_size(pid)
        ok = 0
        for i in range(args.rounds):
            print(f"[{pid}] round {i + 1}/{args.rounds}")
            if args.docker:
                prod = _docker_capture(pid, args.timeout)
            else:
                from python_signatures.capture_service import capture_profile_live
                res = capture_profile_live(pid, timeout=args.timeout)
                prod = res.prod if res.ok else None

            if not prod or not prod.get("i1"):
                print(f"  FAIL", file=sys.stderr)
                continue
            save_capture_to_pool(pid, prod, index=before + ok + 1)
            ok += 1
            print(f"  OK slots={[k for k in ('i1','i2','i3','i4','i5') if prod.get(k)]}")

        print(f"{pid}: added {ok}/{args.rounds}, pool={pool_size(pid)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
