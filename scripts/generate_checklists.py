#!/usr/bin/env python3
"""Generate protocol_workbook CHECKLIST.md files for all profiles."""

from pathlib import Path

PROFILES = {
    "dns": {
        "rfc": "RFC 1035",
        "packets": "1 query + up to 4 responses",
        "max_slots": 5,
        "required": "i1",
        "collector": "dns_collector.py (dig + tcpdump live)",
    },
    "sip": {
        "rfc": "RFC 3261",
        "packets": "OPTIONS, 200 OK, REGISTER sequence",
        "max_slots": 5,
        "required": "i1, i2",
        "collector": "sip_dtls_collector.SipSignatureCollector",
    },
    "dtls": {
        "rfc": "RFC 6347",
        "packets": "DTLS records (ClientHello, handshake)",
        "max_slots": 5,
        "required": "i1, i2",
        "collector": "sip_dtls_collector.DtlsSignatureCollector",
    },
    "quic": {
        "rfc": "RFC 9000",
        "packets": "QUIC long-header Initial/Handshake chain",
        "max_slots": 5,
        "required": "i1-i5",
        "collector": "browser_quic_collector.py",
    },
    "quic_browser": {
        "rfc": "RFC 9000 + HTTP/3",
        "packets": "Chromium QUIC chain up to 5 UDP",
        "max_slots": 5,
        "required": "i1-i5",
        "collector": "browser_quic_collector.py + browser_capture",
    },
    "stun": {
        "rfc": "RFC 5389",
        "packets": "STUN Binding request (+ optional response)",
        "max_slots": 2,
        "required": "i1",
        "collector": "browser_stun_collector.py",
    },
    "webrtc": {
        "rfc": "RFC 5389 via WebRTC ICE",
        "packets": "STUN Binding via ICE",
        "max_slots": 2,
        "required": "i1",
        "collector": "browser_stun_collector.py",
    },
    "stun_browser": {
        "rfc": "RFC 5389",
        "packets": "STUN Binding request + response",
        "max_slots": 2,
        "required": "i1, i2",
        "collector": "browser_stun_collector.py + cps_specs/stun_browser.yaml",
    },
}

TEMPLATE = """# CHECKLIST: {pid}

## A — Semantics
- [ ] Spec: {rfc}
- [ ] Typical UDP packets: {packets}
- [ ] Fixed vs variable fields documented
- [ ] Target chain length: max {max_slots} slots
- [ ] Empty optional slots policy: omit line (never `I2=` empty)

## B — Capture
- [ ] Collector: `{collector}`
- [ ] BPF filter documented in workbook notes
- [ ] Live run (WSL): `poetry run python audit_capture.py --profile {pid} --strict`
- [ ] Pcap saved under `captures/`
- [ ] `poetry run python analyze_pcap.py --pcap captures/run1.pcap`

## C — CPS mapping
- [ ] Per-slot: full `<b 0x>` or hybrid (`cps_specs/{pid}.yaml`)
- [ ] Variable fields use `<r>`, `<t>`, `<rc>` where required
- [ ] CPS validator: 0 errors

## D — Verification
- [ ] `slot_sources` has no `architect` in strict mode
- [ ] `compare_architect.py --profile {pid}` reviewed
- [ ] 3 stable captures (live) or fixture documented (dry-run)

## E — Slot policy
- [ ] Required slots: {required}
- [ ] Documented in `capture_policy.yaml`
- [ ] `export_for_panel()` omits empty slots

## Status
- [ ] Definition of Done (plan phase 6)
"""


def main() -> None:
    base = Path(__file__).resolve().parent / "protocol_workbook"
    for pid, meta in PROFILES.items():
        d = base / pid / "captures"
        d.mkdir(parents=True, exist_ok=True)
        (base / pid / "CHECKLIST.md").write_text(
            TEMPLATE.format(pid=pid, **meta),
            encoding="utf-8",
        )
        print(f"Wrote {pid}/CHECKLIST.md")


if __name__ == "__main__":
    main()
