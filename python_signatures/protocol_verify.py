"""
Protocol-specific slot verification for live capture (signature-lab).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from python_signatures.provenance import SLOT_KEYS, validate_cps
from python_signatures.quic_verify import (
    QuicSlotReport,
    parse_pure_b_tag,
    print_verification_report,
    verify_quic_payload,
    verify_quic_slots,
)

_STUN_MAGIC = bytes.fromhex("2112a442")


@dataclass
class SlotReport:
    slot: str
    present: bool
    byte_len: int = 0
    protocol: str = ""
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.present and not self.issues


def _base_reports(profile: Dict[str, Any], protocol: str) -> List[SlotReport]:
    reports: List[SlotReport] = []
    for slot in SLOT_KEYS:
        val = profile.get(slot)
        if not isinstance(val, str) or not val.strip():
            continue
        for issue in validate_cps(val, slot=slot):
            if issue.severity == "error":
                reports.append(SlotReport(slot=slot, present=True, protocol=protocol, issues=[issue.message]))
                break
        else:
            payload = parse_pure_b_tag(val)
            if payload is None:
                reports.append(
                    SlotReport(
                        slot=slot,
                        present=True,
                        protocol=protocol,
                        issues=["expected single pure <b 0xHEX> tag"],
                    )
                )
                continue
            reports.append(SlotReport(slot=slot, present=True, byte_len=len(payload), protocol=protocol))
    return reports


def verify_stun_slots(profile: Dict[str, Any]) -> List[SlotReport]:
    reports = _base_reports(profile, "stun")
    for rep in reports:
        payload = parse_pure_b_tag(str(profile.get(rep.slot, "")))
        if payload is None:
            continue
        if len(payload) < 20:
            rep.issues.append(f"STUN too short ({len(payload)} < 20)")
        if payload[4:8] != _STUN_MAGIC:
            rep.issues.append("missing STUN magic cookie 0x2112A442 at offset 4")
        msg_type = int.from_bytes(payload[0:2], "big")
        if rep.slot == "i1" and msg_type != 0x0001:
            rep.warnings.append(f"I1 type 0x{msg_type:04x} (expected Binding Request 0x0001)")
        if rep.slot == "i2" and msg_type != 0x0101:
            rep.warnings.append(f"I2 type 0x{msg_type:04x} (expected Binding Response 0x0101)")
    return reports


def verify_dns_slots(profile: Dict[str, Any]) -> List[SlotReport]:
    reports = _base_reports(profile, "dns")
    for rep in reports:
        payload = parse_pure_b_tag(str(profile.get(rep.slot, "")))
        if payload is None:
            continue
        if len(payload) < 12:
            rep.issues.append(f"DNS too short ({len(payload)} < 12)")
            continue
        flags = int.from_bytes(payload[2:4], "big")
        is_response = bool(flags & 0x8000)
        if rep.slot == "i1" and is_response:
            rep.issues.append("I1 must be DNS query (QR=0)")
        if rep.slot != "i1" and not is_response:
            rep.warnings.append(f"{rep.slot.upper()} is query, expected response")
    return reports


def verify_tls_clienthello(payload: bytes) -> List[str]:
    issues: List[str] = []
    if len(payload) < 6:
        issues.append(f"TLS too short ({len(payload)} < 6)")
        return issues
    if payload[0] != 0x16:
        issues.append(f"expected TLS handshake record 0x16, got 0x{payload[0]:02x}")
    return issues


def verify_quic_tls_slots(profile: Dict[str, Any]) -> List[Any]:
    """I1 = TLS ClientHello; I2-I5 = QUIC."""
    reports: List[Any] = []
    i1_val = profile.get("i1")
    if isinstance(i1_val, str) and i1_val.strip():
        payload = parse_pure_b_tag(i1_val)
        if payload is None:
            reports.append(SlotReport(slot="i1", present=True, protocol="tls", issues=["expected pure <b 0xHEX>"]))
        else:
            rep = SlotReport(slot="i1", present=True, byte_len=len(payload), protocol="tls")
            rep.issues.extend(verify_tls_clienthello(payload))
            reports.append(rep)
    quic_part = {k: profile[k] for k in ("i2", "i3", "i4", "i5") if k in profile}
    if quic_part:
        for qr in verify_quic_slots(quic_part):
            qr.slot = qr.slot  # already i2-i5
            reports.append(qr)
    return reports


def verify_ntp_slots(profile: Dict[str, Any]) -> List[SlotReport]:
    reports = _base_reports(profile, "ntp")
    for rep in reports:
        payload = parse_pure_b_tag(str(profile.get(rep.slot, "")))
        if payload is None:
            continue
        if len(payload) < 48:
            rep.warnings.append(f"NTP packet shorter than 48B ({len(payload)}B)")
        if rep.slot == "i1" and len(payload) >= 1:
            vn_mode = payload[0]
            mode = vn_mode & 0x07
            if mode != 3:
                rep.warnings.append(f"I1 NTP mode {mode} (expected client mode 3)")
    return reports


def verify_generic_slots(profile: Dict[str, Any], protocol: str) -> List[SlotReport]:
    reports = _base_reports(profile, protocol)
    for rep in reports:
        if rep.byte_len < 1:
            rep.issues.append("empty payload")
    return reports


def verify_profile_slots(profile_id: str, profile: Dict[str, Any]) -> List[Any]:
    if profile_id in ("quic", "quic_browser"):
        return verify_quic_slots(profile)
    if profile_id == "quic_tls_browser":
        return verify_quic_tls_slots(profile)
    if profile_id in ("stun", "stun_browser", "webrtc"):
        return verify_stun_slots(profile)
    if profile_id == "dns":
        return verify_dns_slots(profile)
    if profile_id == "ntp":
        return verify_ntp_slots(profile)
    return verify_generic_slots(profile, profile_id)


def print_slot_reports(reports: List[Any]) -> None:
    for r in reports:
        if isinstance(r, QuicSlotReport):
            print_verification_report([r])
            continue
        status = "OK" if r.ok else "FAIL"
        extra = f" {r.byte_len}B" if r.byte_len else ""
        proto = getattr(r, "protocol", "") or "?"
        print(f"  [{status}] {r.slot.upper()}{extra} ({proto})")
        for w in r.warnings:
            print(f"    warn: {w}")
        for i in r.issues:
            print(f"    err: {i}")


def reports_to_dicts(reports: List[Any]) -> List[Dict[str, Any]]:
    return [asdict(r) for r in reports]
