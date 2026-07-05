"""Unified CLI for signature-lab (standalone + wg-easy panel bridge)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_LAB = Path(__file__).resolve().parent.parent
if str(_LAB) not in sys.path:
    sys.path.insert(0, str(_LAB))

from python_signatures.capture_service import capture_profile_live
from python_signatures.export_formats import (
    lab_batch_to_panel,
    merge_profile_into_panel,
    prod_to_conf_lines,
    to_panel_entry,
    write_panel_file,
)
from python_signatures.provenance import export_prod_profile
from python_signatures.features import (
    BROWSER_PROFILE_IDS,
    browser_capture_available,
    browser_disabled_by_env,
    profile_available,
    unavailable_reason,
)
from python_signatures.run_all import PROTOCOL_REGISTRY, run_all


def _json_out(data: Any) -> int:
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    all_ids = [p[0] for p in PROTOCOL_REGISTRY]
    available = [p for p in all_ids if profile_available(p)]
    payload = {
        "profile_ids": available if args.available_only else all_ids,
        "all_profile_ids": all_ids,
        "available_profile_ids": available,
        "browser_profiles": sorted(BROWSER_PROFILE_IDS),
        "browser_enabled": browser_capture_available(),
        "browser_disabled_env": browser_disabled_by_env(),
        "default_profile": available[0] if available else (all_ids[0] if all_ids else "dns"),
    }
    if args.json:
        return _json_out(payload)
    for pid in payload["profile_ids"]:
        mark = "" if profile_available(pid) else f" (unavailable: {unavailable_reason(pid)})"
        print(f"  {pid}{mark}")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    profile_id = args.profile.strip()

    if args.docker:
        from siglab.docker_runner import docker_available, run_capture_in_docker

        if not docker_available():
            print("ERROR: docker not available", file=sys.stderr)
            return 1
        result = run_capture_in_docker(
            profile_id,
            timeout=args.timeout,
            build=not args.no_build,
        )
        if not result.get("ok"):
            if args.json:
                return _json_out(result)
            print(f"FAIL: {result.get('error')}", file=sys.stderr)
            return 1
        prod = result["prod"]
    else:
        res = capture_profile_live(
            profile_id,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
        if not res.ok:
            err = {"ok": False, "profile_id": profile_id, "error": res.error, "verification": res.verification}
            if args.json:
                return _json_out(err)
            print(f"FAIL: {res.error}", file=sys.stderr)
            return 1
        prod = res.prod
        if args.debug_out:
            args.debug_out.parent.mkdir(parents=True, exist_ok=True)
            args.debug_out.write_text(
                json.dumps(res.to_debug_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    fmt = args.format
    out_path = args.out

    if fmt == "prod":
        payload = prod
    elif fmt == "panel":
        payload = {profile_id: to_panel_entry(prod)}
    elif fmt == "conf":
        text = prod_to_conf_lines(prod)
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
            if args.json:
                return _json_out({"ok": True, "profile_id": profile_id, "out": str(out_path), "format": "conf"})
            print(f"OK conf -> {out_path}")
            return 0
        print(text, end="")
        return 0
    else:
        payload = prod

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "panel" and args.merge_into:
            merge_profile_into_panel(args.merge_into, profile_id, to_panel_entry(prod))
            if args.json:
                return _json_out({
                    "ok": True,
                    "profile_id": profile_id,
                    "merged_into": str(args.merge_into),
                    "slots": sorted(to_panel_entry(prod).keys()),
                })
            print(f"OK merged {profile_id} into {args.merge_into}")
            return 0
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if args.json:
            return _json_out({"ok": True, "profile_id": profile_id, "out": str(out_path), "format": fmt})
        print(f"OK {profile_id} -> {out_path}")
        return 0

    if args.json:
        return _json_out({"ok": True, "profile_id": profile_id, "prod": prod})
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    config_dir = args.config_dir or (_LAB / "python_signatures" / "config")
    out_path = args.out
    data = run_all(
        config_dir,
        out_path,
        timeout=args.timeout,
        dry_run=args.dry_run,
        strict=args.strict,
        policy_path=args.policy,
        skip_errors=True,
        available_only=not args.include_unavailable,
    )
    if args.format == "panel":
        panel = lab_batch_to_panel(data)
        write_panel_file(out_path, panel)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        return _json_out({
            "ok": True,
            "out": str(out_path),
            "format": args.format,
            "profiles": list((data.get("profiles") or data).keys()) if isinstance(data, dict) else [],
        })
    print(f"OK batch -> {out_path}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    src = Path(args.input)
    raw = json.loads(src.read_text(encoding="utf-8"))
    pid = args.profile

    if pid in raw and isinstance(raw[pid], dict):
        entry = raw[pid]
    elif "profiles" in raw and pid in raw["profiles"]:
        entry = raw["profiles"][pid]
    elif pid in raw.get("prod", {}):
        entry = raw["prod"]
    elif raw.get("profile_id") == pid:
        entry = raw
    else:
        print(f"profile {pid!r} not found in {src}", file=sys.stderr)
        return 1

    if args.format == "conf":
        text = prod_to_conf_lines(entry if "i1" in entry else {"i1": entry.get("hex", "")})
        if args.out:
            args.out.write_text(text, encoding="utf-8")
            print(f"OK conf -> {args.out}")
        else:
            print(text, end="")
        return 0

    if args.format == "panel":
        payload = {pid: to_panel_entry(entry)}
    else:
        payload = export_prod_profile(entry, profile_id=pid) if "slot_sources" in entry else entry

    if args.out:
        args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"OK -> {args.out}")
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    from python_signatures.template_pool import pool_size

    profiles = []
    for pid, _, _ in PROTOCOL_REGISTRY:
        profiles.append({
            "profile_id": pid,
            "requires_browser": pid in BROWSER_PROFILE_IDS,
            "available": profile_available(pid),
            "unavailable_reason": unavailable_reason(pid),
            "pool_size": pool_size(pid),
        })
    payload = {
        "browser_enabled": browser_capture_available(),
        "browser_disabled_env": browser_disabled_by_env(),
        "profiles": profiles,
    }
    return _json_out(payload) if args.json else (print(json.dumps(payload, indent=2)) or 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siglab",
        description="Signature-lab: capture I1-I5 profiles for AmneziaWG (standalone + panel bridge).",
    )
    p.add_argument("--json", action="store_true", help="Machine-readable JSON on stdout")
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("list", help="List profile_ids (optionally only available)")
    pl.add_argument("--available-only", action="store_true")
    pl.set_defaults(func=cmd_list)

    pc = sub.add_parser("capture", help="Capture one profile")
    pc.add_argument("--profile", required=True)
    pc.add_argument("--out", type=Path, default=None)
    pc.add_argument("--debug-out", type=Path, default=None)
    pc.add_argument("--format", choices=("prod", "panel", "conf"), default="prod")
    pc.add_argument("--merge-into", type=Path, default=None, help="Merge panel entry into signatures.json")
    pc.add_argument("--timeout", type=int, default=None)
    pc.add_argument("--dry-run", action="store_true")
    pc.add_argument("--docker", action="store_true", help="Run capture inside Docker (browser/tcpdump)")
    pc.add_argument("--no-build", action="store_true", help="Skip docker build with --docker")
    pc.set_defaults(func=cmd_capture)

    pb = sub.add_parser("batch", help="Run all available collectors")
    pb.add_argument("--out", type=Path, required=True)
    pb.add_argument("--config-dir", type=Path, default=None)
    pb.add_argument("--policy", type=Path, default=None)
    pb.add_argument("--timeout", type=int, default=30)
    pb.add_argument("--dry-run", action="store_true")
    pb.add_argument("--strict", action="store_true")
    pb.add_argument("--format", choices=("lab", "panel"), default="lab")
    pb.add_argument("--include-unavailable", action="store_true", help="Try browser profiles even if deps missing")
    pb.set_defaults(func=cmd_batch)

    pe = sub.add_parser("export", help="Convert captured JSON to panel/conf format")
    pe.add_argument("--profile", required=True)
    pe.add_argument("--input", type=Path, required=True)
    pe.add_argument("--out", type=Path, default=None)
    pe.add_argument("--format", choices=("prod", "panel", "conf"), default="conf")
    pe.set_defaults(func=cmd_export)

    pk = sub.add_parser("capabilities", help="Report browser/template availability")
    pk.set_defaults(func=cmd_capabilities)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
