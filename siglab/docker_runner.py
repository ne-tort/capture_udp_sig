"""Docker live capture runner for siglab (Windows/Linux hosts with Docker Desktop)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def _lab_root() -> Path:
    return Path(__file__).resolve().parent.parent


def docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _image_for_profile(profile_id: str) -> tuple[str, str]:
    from python_signatures.features import profile_requires_browser

    if profile_requires_browser(profile_id):
        return "Dockerfile.capture", "signature-lab-capture"
    return "Dockerfile.capture-lite", "signature-lab-capture-lite"


def build_capture_image(
    *,
    lab_root: Optional[Path] = None,
    tag: Optional[str] = None,
    profile_id: str = "dns",
    quiet: bool = False,
) -> str:
    root = lab_root or _lab_root()
    dockerfile, default_tag = _image_for_profile(profile_id)
    image_tag = tag or default_tag
    env = dict(__import__("os").environ)
    env["DOCKER_BUILDKIT"] = "1"
    subprocess.run(
        [
            "docker", "build",
            "--cache-from", f"{image_tag}:latest",
            "-f", str(root / dockerfile),
            "-t", image_tag,
            str(root),
        ],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    return image_tag


def run_capture_in_docker(
    profile_id: str,
    *,
    lab_root: Optional[Path] = None,
    tag: Optional[str] = None,
    timeout: Optional[int] = None,
    build: bool = True,
    quiet: bool = False,
    mount_sources: bool = True,
) -> Dict[str, Any]:
    """
    Build (optional) and run live capture in Docker; read prod JSON from host output/.
    """
    root = lab_root or _lab_root()
    out_dir = root / "output"
    out_dir.mkdir(parents=True, exist_ok=True)

    _, default_tag = _image_for_profile(profile_id)
    image_tag = tag or default_tag

    if build:
        build_capture_image(lab_root=root, tag=image_tag, profile_id=profile_id, quiet=quiet)

    cmd = [
        "docker", "run", "--rm",
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        "-v", f"{out_dir}:/lab/output",
    ]
    if mount_sources:
        cmd.extend([
            "-v", f"{root / 'python_signatures'}:/lab/python_signatures",
            "-v", f"{root / 'capture_policy.yaml'}:/lab/capture_policy.yaml",
        ])
    cmd.extend([image_tag, profile_id])
    if timeout is not None:
        cmd.append(str(timeout))

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not quiet:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)

    prod_path = out_dir / f"live_{profile_id}.json"
    debug_path = out_dir / f"live_{profile_id}_debug.json"

    if proc.returncode != 0:
        return {
            "ok": False,
            "profile_id": profile_id,
            "error": proc.stderr.strip() or f"docker exit {proc.returncode}",
            "prod_path": str(prod_path),
        }

    if not prod_path.is_file():
        return {"ok": False, "profile_id": profile_id, "error": f"missing {prod_path}"}

    prod = json.loads(prod_path.read_text(encoding="utf-8"))
    debug = json.loads(debug_path.read_text(encoding="utf-8")) if debug_path.is_file() else {}
    return {
        "ok": bool(prod.get("ok")),
        "profile_id": profile_id,
        "prod": prod,
        "debug": debug,
        "prod_path": str(prod_path),
        "debug_path": str(debug_path),
    }
