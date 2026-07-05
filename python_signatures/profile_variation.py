"""
Per-profile variation limits for signature bank builds.

Static analysis of collectors/configs: which profiles can produce meaningfully
different i1-i5 across repeated live captures without changing targets/URLs.
"""

from __future__ import annotations

from typing import Dict, Literal, TypedDict

VariationKind = Literal["variable", "static"]


class ProfileVariation(TypedDict):
    kind: VariationKind
    max_useful: int
    reason: str


# max_useful=1 → one live capture is enough; higher only where payload entropy exists.
PROFILE_VARIATION: Dict[str, ProfileVariation] = {
    "dns": {
        "kind": "variable",
        "max_useful": 1000,
        "reason": "dig random TXID; 8 domains × A/AAAA fill i2-i5 in one shot",
    },
    "dtls": {
        "kind": "variable",
        "max_useful": 1000,
        "reason": "OpenSSL ClientHello random bytes each handshake",
    },
    "sip": {
        "kind": "static",
        "max_useful": 1,
        "reason": "fixed OPTIONS template (seq=1, constant branch/Call-ID)",
    },
    "sip_multi": {
        "kind": "static",
        "max_useful": 1,
        "reason": "fixed 3-round OPTIONS chain (seq 1..3 every run)",
    },
    "ntp": {
        "kind": "static",
        "max_useful": 1,
        "reason": "fixed 48-byte mode-3 request (0x1b + zeros)",
    },
    "quic": {
        "kind": "static",
        "max_useful": 1,
        "reason": "stable Chromium QUIC Initial per URL; 3 URLs tried per capture",
    },
    "quic_browser": {
        "kind": "static",
        "max_useful": 1,
        "reason": "stable Chromium QUIC Initial per URL; no per-run randomness in I-slots",
    },
    "quic_tls_browser": {
        "kind": "static",
        "max_useful": 1,
        "reason": "TLS ClientHello + QUIC chain fixed for same alt-svc URL set",
    },
    "stun": {
        "kind": "static",
        "max_useful": 1,
        "reason": "single STUN Binding template; 2 Google servers, same packet shape",
    },
    "stun_browser": {
        "kind": "static",
        "max_useful": 1,
        "reason": "WebRTC STUN via Chromium — fingerprint-stable per server URL",
    },
    "webrtc": {
        "kind": "static",
        "max_useful": 1,
        "reason": "outbound-only STUN Binding; same structure per server",
    },
}


def profile_variation(profile_id: str) -> ProfileVariation:
    return PROFILE_VARIATION.get(profile_id, {
        "kind": "static",
        "max_useful": 1,
        "reason": "unknown profile",
    })


def effective_target(profile_id: str, requested: int) -> int:
    cap = profile_variation(profile_id)["max_useful"]
    return max(1, min(requested, cap))
