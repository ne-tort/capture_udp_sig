"""
Verify QUIC capture slots before prod export (signature-lab).

Checks hex round-trip, CPS shape, and RFC 9000 long-header heuristics.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from python_signatures.provenance import SLOT_KEYS, validate_cps

_B_TAG_RE = re.compile(r"^<b\s+0x([0-9a-fA-F]+)>$", re.IGNORECASE)
_QUIC_V1 = 0x00000001

# Client Initial is often padded to ~1200 B; full datagram payload rarely exceeds 1452 B.
_MIN_BYTES = 20
_WARN_MIN_BYTES = 100
_MAX_WARN_BYTES = 1452


@dataclass
class QuicSlotReport:
    slot: str
    present: bool
    byte_len: int = 0
    hex_nibbles: int = 0
    protocol: str = "quic"
    long_header: bool = False
    quic_version: Optional[int] = None
    packet_type: str = "missing"
    distinct: bool = True
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.present and not self.issues


def parse_pure_b_tag(cps: str) -> Optional[bytes]:
    if not isinstance(cps, str):
        return None
    s = cps.strip()
    m = _B_TAG_RE.match(s)
    if not m:
        return None
    hx = m.group(1)
    if len(hx) % 2:
        return None
    try:
        return bytes.fromhex(hx)
    except ValueError:
        return None


def _packet_type_name(first_byte: int) -> str:
    if (first_byte & 0x80) == 0:
        return "short"
    typ = (first_byte & 0x30) >> 4
    return {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}.get(typ, "unknown_long")


def verify_quic_payload(payload: bytes, *, slot: str) -> QuicSlotReport:
    rep = QuicSlotReport(slot=slot, present=True, byte_len=len(payload), hex_nibbles=len(payload) * 2)

    if len(payload) < _MIN_BYTES:
        rep.issues.append(f"payload too short ({len(payload)} < {_MIN_BYTES})")
    elif len(payload) < _WARN_MIN_BYTES:
        rep.warnings.append(f"payload unusually short ({len(payload)} B)")

    if len(payload) > _MAX_WARN_BYTES:
        rep.warnings.append(f"payload large ({len(payload)} > {_MAX_WARN_BYTES} B)")

    rep.long_header = (payload[0] & 0x80) != 0
    if not rep.long_header:
        rep.warnings.append("short header (not typical for I-slot first flights)")

    if len(payload) >= 5:
        rep.quic_version = int.from_bytes(payload[1:5], "big")
        if rep.quic_version not in (_QUIC_V1, 0x6B3343CF, 0xFF00001D) and rep.quic_version < 0xFF000000:
            rep.warnings.append(f"non-standard QUIC version 0x{rep.quic_version:08x}")

    rep.packet_type = _packet_type_name(payload[0])
    if rep.long_header and rep.packet_type not in ("initial", "0rtt", "handshake"):
        rep.warnings.append(f"unexpected long-header type: {rep.packet_type}")

    return rep


def verify_quic_slots(profile: Dict[str, Any]) -> List[QuicSlotReport]:
    """Verify filled I slots; empty slots are skipped (prod omit)."""
    reports: List[QuicSlotReport] = []
    seen: Dict[bytes, str] = {}

    for slot in SLOT_KEYS:
        val = profile.get(slot)
        if not isinstance(val, str) or not val.strip():
            continue

        for issue in validate_cps(val, slot=slot):
            if issue.severity == "error":
                rep = QuicSlotReport(slot=slot, present=True, issues=[issue.message])
                reports.append(rep)
                break
        else:
            payload = parse_pure_b_tag(val)
            if payload is None:
                rep = QuicSlotReport(
                    slot=slot,
                    present=True,
                    issues=["expected single pure <b 0xHEX> tag (capture format)"],
                )
                reports.append(rep)
                continue

            rep = verify_quic_payload(payload, slot=slot)
            if payload in seen:
                rep.distinct = False
                rep.warnings.append(f"duplicate payload of {seen[payload]}")
            else:
                seen[payload] = slot
            reports.append(rep)

    return reports


def reports_to_dicts(reports: List[QuicSlotReport]) -> List[Dict[str, Any]]:
    return [asdict(r) for r in reports]


def print_verification_report(reports: List[QuicSlotReport]) -> None:
    for r in reports:
        status = "OK" if r.ok else "FAIL"
        extra = f" {r.byte_len}B {r.packet_type} ver={r.quic_version}" if r.present else ""
        print(f"  [{status}] {r.slot.upper()}{extra}")
        for w in r.warnings:
            print(f"    warn: {w}")
        for i in r.issues:
            print(f"    err: {i}")
