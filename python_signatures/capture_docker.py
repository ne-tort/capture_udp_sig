"""
Docker-sidecar capture (Playwright + tcpdump in capture-udp-sig image).
Used by wg-easy panel on Alpine where native browser deps are unavailable.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


def capture_image_tag() -> str:
    return os.environ.get("CAPTURE_IMAGE", "capture-udp-sig:local").strip() or "capture-udp-sig:local"


def capture_docker_enabled() -> bool:
    v = os.environ.get("CAPTURE_DOCKER", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def docker_cli_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def capture_image_available(tag: Optional[str] = None) -> bool:
    image = tag or capture_image_tag()
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def capture_via_docker() -> bool:
    """Docker sidecar (capture-udp-sig image) available for live capture from panel."""
    return capture_docker_enabled() and docker_cli_available() and capture_image_available()


def browser_capture_via_docker() -> bool:
    return capture_via_docker()


def run_profile_capture_docker(
    profile_id: str,
    *,
    lab_root: Path,
    timeout: Optional[int] = None,
    tag: Optional[str] = None,
) -> Dict[str, Any]:
    """Run capture in sidecar container; copy prod JSON out via docker cp."""
    image = tag or capture_image_tag()
    name = f"capture-{profile_id}-{uuid.uuid4().hex[:8]}"
    cmd = [
        "docker", "run",
        "--name", name,
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        image,
        profile_id,
    ]
    if timeout is not None:
        cmd.append(str(timeout))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout or 60) + 120)
    out_dir = lab_root / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    prod_path = out_dir / f"live_{profile_id}.json"
    debug_path = out_dir / f"live_{profile_id}_debug.json"

    try:
        if proc.returncode != 0:
            return {
                "ok": False,
                "profile_id": profile_id,
                "error": (proc.stderr or proc.stdout or f"docker exit {proc.returncode}").strip(),
            }

        cp_prod = subprocess.run(
            ["docker", "cp", f"{name}:/lab/output/live_{profile_id}.json", str(prod_path)],
            capture_output=True,
            text=True,
        )
        if cp_prod.returncode != 0:
            return {
                "ok": False,
                "profile_id": profile_id,
                "error": cp_prod.stderr.strip() or "docker cp prod failed",
            }

        subprocess.run(
            ["docker", "cp", f"{name}:/lab/output/live_{profile_id}_debug.json", str(debug_path)],
            capture_output=True,
            text=True,
        )

        prod = json.loads(prod_path.read_text(encoding="utf-8"))
        return {
            "ok": bool(prod.get("ok", prod.get("i1"))),
            "profile_id": profile_id,
            "prod": prod,
            "prod_path": str(prod_path),
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
