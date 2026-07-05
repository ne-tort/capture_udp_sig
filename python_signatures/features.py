"""
Runtime capability flags (browser capture optional).
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import FrozenSet

BROWSER_PROFILE_IDS: FrozenSet[str] = frozenset({
    "quic",
    "quic_browser",
    "quic_tls_browser",
    "stun",
    "stun_browser",
    "webrtc",
})


def browser_disabled_by_env() -> bool:
    for key in ("CAPTURE_NO_BROWSER", "SIGLAB_NO_BROWSER"):
        v = os.environ.get(key, "").strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
    return False


@lru_cache(maxsize=1)
def browser_capture_importable() -> bool:
    if browser_disabled_by_env():
        return False
    try:
        from browser_capture.core.orchestrator import CaptureOrchestrator  # noqa: F401
        return True
    except ImportError:
        return False


def _sidecar_capture_available() -> bool:
    try:
        from python_signatures.capture_docker import capture_via_docker
        return capture_via_docker()
    except ImportError:
        return False


def browser_capture_available() -> bool:
    if browser_disabled_by_env():
        return False
    if browser_capture_importable():
        return True
    return _sidecar_capture_available()


def live_capture_available() -> bool:
    if os.environ.get("CAPTURE_IN_DOCKER") == "1":
        return True
    if _sidecar_capture_available():
        return True
    if browser_capture_importable():
        return True
    return not browser_disabled_by_env()


def profile_requires_browser(profile_id: str) -> bool:
    return profile_id in BROWSER_PROFILE_IDS


def profile_available(profile_id: str, *, dry_run: bool = False) -> bool:
    if dry_run:
        return True
    if profile_requires_browser(profile_id) and browser_disabled_by_env():
        return False
    if os.environ.get("CAPTURE_IN_DOCKER") == "1":
        if profile_requires_browser(profile_id):
            return browser_capture_importable()
        return True
    if _sidecar_capture_available():
        return True
    if profile_requires_browser(profile_id):
        return browser_capture_available()
    return True


def unavailable_reason(profile_id: str) -> str | None:
    if profile_requires_browser(profile_id) and browser_disabled_by_env():
        return "browser capture disabled (CAPTURE_NO_BROWSER)"
    if profile_available(profile_id):
        return None
    if not _sidecar_capture_available():
        from python_signatures.capture_docker import (
            capture_docker_enabled,
            capture_image_available,
            docker_cli_available,
        )
        if capture_docker_enabled() and not docker_cli_available():
            return "docker CLI unavailable (mount /var/run/docker.sock)"
        if capture_docker_enabled() and not capture_image_available():
            return "capture image missing (build capture-udp-sig:local)"
    if profile_requires_browser(profile_id):
        return "browser-capture not available"
    return "live capture not available"
