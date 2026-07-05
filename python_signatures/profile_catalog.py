"""
UI catalog for obfuscation profiles (labels, descriptions).
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.features import profile_requires_browser
from python_signatures.run_all import PROTOCOL_REGISTRY

# profile_id -> display metadata for wg-easy panel
CATALOG: Dict[str, Dict[str, str]] = {
    "dns": {"label": "DNS", "description": "UDP DNS queries (dig)"},
    "sip": {"label": "SIP", "description": "SIP OPTIONS (single server)"},
    "sip_multi": {"label": "SIP multi", "description": "SIP OPTIONS (several servers)"},
    "dtls": {"label": "DTLS", "description": "DTLS handshake (DoT-style)"},
    "ntp": {"label": "NTP", "description": "NTP client poll"},
    "quic": {"label": "QUIC", "description": "QUIC / HTTP3 (browser capture)"},
    "quic_browser": {"label": "QUIC browser", "description": "QUIC via Chromium navigation"},
    "quic_tls_browser": {"label": "QUIC+TLS browser", "description": "QUIC with TLS fingerprint (browser)"},
    "stun": {"label": "STUN", "description": "STUN binding (UDP)"},
    "stun_browser": {"label": "STUN browser", "description": "STUN via WebRTC in browser"},
    "webrtc": {"label": "WebRTC", "description": "WebRTC STUN (outbound only)"},
}


def catalog_entry(profile_id: str) -> Dict[str, Any]:
    meta = CATALOG.get(profile_id, {})
    return {
        "profile_id": profile_id,
        "label": meta.get("label") or profile_id,
        "description": meta.get("description") or "",
        "requires_browser": profile_requires_browser(profile_id),
    }


def all_catalog_entries() -> List[Dict[str, Any]]:
    order = [p[0] for p in PROTOCOL_REGISTRY]
    return [catalog_entry(pid) for pid in order]
