#!/usr/bin/env python3
"""
Build a unified signature bank: one JSON file, N numbered iterations per profile.

Resume-safe (atomic append), Docker capture with browser profiles.
Static protocols capped at 1 variant; duplicates stop further iterations.
429 → skip entire protocol.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

warnings.filterwarnings("ignore", message="No libpcap provider")

_LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_LAB))

from python_signatures.features import profile_requires_browser  # noqa: E402
from python_signatures.profile_variation import effective_target, profile_variation  # noqa: E402
from python_signatures.run_all import PROTOCOL_REGISTRY  # noqa: E402
from python_signatures.signature_bank import (  # noqa: E402
    append_entry,
    entry_from_prod,
    get_profile_status,
    is_duplicate_i1,
    is_rate_limited,
    is_transient_error,
    load_bank,
    next_iteration,
    profile_count,
    save_bank,
    set_profile_status,
    slots_label,
)


def _log(msg: str) -> None:
    print(msg, flush=True)


def _short_error(err: str, *, max_len: int = 80) -> str:
    for raw in (err or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Traceback"):
            continue
        if line.startswith("File "):
            continue
        if len(line) > max_len:
            return line[: max_len - 3] + "..."
        return line
    line = (err or "error").strip().splitlines()[-1].strip() if err else "error"
    if len(line) > max_len:
        return line[: max_len - 3] + "..."
    return line


def _capture_docker(
    profile_id: str,
    *,
    timeout: int,
    build: bool,
    image_lite: str,
    image_browser: str,
) -> tuple[Optional[Dict[str, str]], str, bool]:
    from siglab.docker_runner import docker_available, run_capture_in_docker

    if not docker_available():
        return None, "docker not available", False

    tag = image_browser if profile_requires_browser(profile_id) else image_lite

    prev = os.environ.pop("CAPTURE_NO_BROWSER", None)
    prev2 = os.environ.pop("SIGLAB_NO_BROWSER", None)
    try:
        result = run_capture_in_docker(
            profile_id,
            timeout=timeout,
            build=build,
            tag=tag,
            quiet=True,
            mount_sources=False,
        )
    finally:
        if prev is not None:
            os.environ["CAPTURE_NO_BROWSER"] = prev
        if prev2 is not None:
            os.environ["SIGLAB_NO_BROWSER"] = prev2

    if not result.get("ok"):
        err = str(result.get("error") or "capture failed")
        need_build = (not build) and ("unable to find image" in err.lower())
        return None, err, need_build
    prod = result.get("prod") or {}
    slots = entry_from_prod(prod)
    if not slots.get("i1"):
        return None, "missing i1 in capture output", False
    return slots, "", False


def _capture_native(profile_id: str, *, timeout: int) -> tuple[Optional[Dict[str, str]], str]:
    from python_signatures.capture_service import capture_profile_live

    res = capture_profile_live(profile_id, timeout=timeout)
    if not res.ok:
        return None, str(res.error or "capture failed")
    slots = entry_from_prod(res.prod)
    if not slots.get("i1"):
        return None, "missing i1 in capture output"
    return slots, ""


def _run_one_capture(
    profile_id: str,
    *,
    timeout: int,
    use_docker: bool,
    build_images: bool,
    image_lite: str,
    image_browser: str,
) -> tuple[Optional[Dict[str, str]], str, bool]:
    if use_docker:
        return _capture_docker(
            profile_id,
            timeout=timeout,
            build=build_images,
            image_lite=image_lite,
            image_browser=image_browser,
        )
    slots, err = _capture_native(profile_id, timeout=timeout)
    return slots, err, False


def _fill_profile(
    bank: Dict[str, Any],
    out_path: Path,
    profile_id: str,
    *,
    requested_target: int,
    timeout: int,
    use_docker: bool,
    build_images: bool,
    max_fail_streak: int,
    delay_ok_sec: float,
    delay_browser_ok_sec: float,
    image_lite: str,
    image_browser: str,
) -> bool:
    var = profile_variation(profile_id)
    target = effective_target(profile_id, requested_target)
    count = profile_count(bank, profile_id)

    prev_status = get_profile_status(bank, profile_id)
    if prev_status and prev_status.get("status") == "skipped_429":
        _log(f"[{profile_id}] skip (429)")
        return True

    if count >= target:
        _log(f"[{profile_id}] {count}/{target} skip (complete)")
        return True

    if target < requested_target:
        _log(f"[{profile_id}] cap {target}/{requested_target} ({var['reason']})")
    elif count:
        _log(f"[{profile_id}] resume {count}/{target}")
    else:
        _log(f"[{profile_id}] start 0/{target}")

    set_profile_status(
        bank,
        profile_id,
        status="static" if var["kind"] == "static" else "variable",
        note=var["reason"],
        effective_target=target,
    )
    save_bank(out_path, bank)

    fail_streak = 0
    built = build_images

    while profile_count(bank, profile_id) < target:
        iteration = next_iteration(bank, profile_id)
        attempt = 0

        while True:
            attempt += 1
            slots, err, need_build = _run_one_capture(
                profile_id,
                timeout=timeout,
                use_docker=use_docker,
                build_images=built,
                image_lite=image_lite,
                image_browser=image_browser,
            )
            if need_build:
                _log(f"[{profile_id}] {iteration}/{target} BUILD image")
                built = True
                continue
            built = False

            if err and is_rate_limited(err):
                set_profile_status(
                    bank, profile_id,
                    status="skipped_429",
                    note="rate limited (429)",
                    effective_target=target,
                )
                save_bank(out_path, bank)
                _log(f"[{profile_id}] SKIP 429")
                return True

            if slots:
                if is_duplicate_i1(bank, profile_id, slots):
                    n = profile_count(bank, profile_id)
                    set_profile_status(
                        bank, profile_id,
                        status="static_dup",
                        note=f"duplicate i1 after {n} capture(s)",
                        effective_target=max(n, 1),
                    )
                    save_bank(out_path, bank)
                    _log(f"[{profile_id}] {n}/{target} STATIC dup — capped")
                    return True

                append_entry(bank, profile_id, iteration, slots)
                save_bank(out_path, bank)
                count = profile_count(bank, profile_id)
                _log(f"[{profile_id}] {count}/{target} OK {slots_label(slots)}")
                fail_streak = 0
                pause = delay_browser_ok_sec if profile_requires_browser(profile_id) else delay_ok_sec
                if pause > 0 and count < target:
                    time.sleep(pause)
                break

            fail_streak += 1
            if is_transient_error(err):
                wait_sec = min(60, 3 * attempt)
                _log(f"[{profile_id}] {iteration}/{target} RETRY {wait_sec}s {_short_error(err)}")
                time.sleep(wait_sec)
            else:
                _log(f"[{profile_id}] {iteration}/{target} FAIL {_short_error(err)}")
                time.sleep(min(30, 2 * attempt))

            if fail_streak >= max_fail_streak:
                _log(f"[{profile_id}] STOP fail_streak={fail_streak} (resume later)")
                return False

    _log(f"[{profile_id}] done {target}/{target}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Build unified signature bank (resume-safe).")
    parser.add_argument(
        "--out",
        type=Path,
        default=_LAB / "output" / "signatures.json",
        help="Output bank file for the panel (default: output/signatures.json)",
    )
    parser.add_argument("--target", type=int, default=1000, help="Iterations per profile (default: 1000)")
    parser.add_argument("--profile", action="append", default=None, help="Profile id (repeatable; default: all)")
    parser.add_argument("--timeout", type=int, default=None, help="Capture timeout override (seconds)")
    parser.add_argument("--docker", action="store_true", default=True, help="Use Docker capture (default)")
    parser.add_argument("--no-docker", action="store_false", dest="docker", help="Native capture (no browser)")
    parser.add_argument("--no-build", action="store_true", help="Skip docker image build")
    parser.add_argument(
        "--image-lite",
        default=os.environ.get("CAPTURE_IMAGE_LITE", "signature-lab-capture-lite"),
        help="Docker tag for non-browser profiles",
    )
    parser.add_argument(
        "--image-browser",
        default=os.environ.get("CAPTURE_IMAGE_BROWSER", "signature-lab-capture"),
        help="Docker tag for browser profiles (quic*, stun*, webrtc)",
    )
    parser.add_argument("--max-fail-streak", type=int, default=20, help="Stop profile after N consecutive fails")
    parser.add_argument("--delay", type=float, default=2.0, help="Pause after OK capture (non-browser), sec")
    parser.add_argument("--delay-browser", type=float, default=5.0, help="Pause after OK browser capture, sec")
    args = parser.parse_args()

    profiles: List[str] = args.profile or [p[0] for p in PROTOCOL_REGISTRY]
    out_path: Path = args.out.resolve()
    bank = load_bank(out_path, default_target=args.target)
    bank["target"] = args.target

    variable_n = sum(1 for p in profiles if profile_variation(p)["kind"] == "variable")
    _log(f"bank {out_path.name} target={args.target} profiles={len(profiles)} variable={variable_n}")

    from python_signatures.capture_timeouts import get_capture_timeout

    all_ok = True
    for pid in profiles:
        tmo = get_capture_timeout(pid, override=args.timeout)
        eff = effective_target(pid, args.target)
        ok = _fill_profile(
            bank,
            out_path,
            pid,
            requested_target=args.target,
            timeout=tmo,
            use_docker=args.docker,
            build_images=not args.no_build,
            max_fail_streak=args.max_fail_streak,
            delay_ok_sec=args.delay,
            delay_browser_ok_sec=args.delay_browser,
            image_lite=args.image_lite,
            image_browser=args.image_browser,
        )
        if not ok:
            all_ok = False

    _log("---")
    for pid in profiles:
        c = profile_count(bank, pid)
        eff = effective_target(pid, args.target)
        st = get_profile_status(bank, pid) or {}
        status = st.get("status", "")
        if status == "skipped_429":
            mark = "SKIP429"
        elif c >= eff:
            mark = "OK"
        else:
            mark = "PARTIAL"
        cap_note = f" cap={eff}" if eff < args.target else ""
        _log(f"{mark} {pid} {c}/{eff}{cap_note}")

    usable = sum(1 for pid in profiles if profile_count(bank, pid) > 0)
    if usable == 0:
        _log("ERROR: bank has no usable profiles (need at least one i1)")
        return 1
    _log(f"panel-ready {out_path} protocols={usable}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

