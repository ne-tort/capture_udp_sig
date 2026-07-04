"""
Runtime capability flags (browser capture optional).
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import FrozenSet

# Profiles that need Playwright + browser_capture (Chromium/tcpdump live path).
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


def browser_capture_available() -> bool:
    return browser_capture_importable() and not browser_disabled_by_env()


def profile_requires_browser(profile_id: str) -> bool:
    return profile_id in BROWSER_PROFILE_IDS


def profile_available(profile_id: str, *, dry_run: bool = False) -> bool:
    if dry_run:
        return True
    if profile_requires_browser(profile_id):
        return browser_capture_available()
    return True


def unavailable_reason(profile_id: str) -> str | None:
    if not profile_requires_browser(profile_id):
        return None
    if browser_disabled_by_env():
        return "browser capture disabled (CAPTURE_NO_BROWSER)"
    if not browser_capture_importable():
        return "browser-capture not installed (poetry install --with browser)"
    return None
