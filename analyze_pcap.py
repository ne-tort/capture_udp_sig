#!/usr/bin/env python3
"""Analyze saved pcap files for protocol workbook (signature-lab)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_LAB_ROOT = Path(__file__).resolve().parent
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

try:
    from scapy.all import IP, UDP, PcapReader  # type: ignore
except ImportError:
    PcapReader = None  # type: ignore

from browser_capture.extractors.quic_udp import is_likely_quic_long_header
from browser_capture.extractors.stun_udp import is_stun_message
from python_signatures.base import SignatureCollector


def _parse_dns(payload: bytes) -> Dict[str, Any]:
    if len(payload) < 12:
        return {"type": "dns", "error": "too short"}
    tid = payload[0:2].hex()
    flags = int.from_bytes(payload[2:4], "big")
    is_response = bool(flags & 0x8000)
    qd = int.from_bytes(payload[4:6], "big")
    return {
        "type": "dns",
        "response": is_response,
        "transaction_id": tid,
        "questions": qd,
        "length": len(payload),
    }


def _parse_stun(payload: bytes) -> Dict[str, Any]:
    if not is_stun_message(payload):
        return {"type": "raw", "length": len(payload)}
    msg_type = int.from_bytes(payload[0:2], "big")
    length = int.from_bytes(payload[2:4], "big")
    txn = payload[8:20].hex()
    return {
        "type": "stun",
        "msg_type": hex(msg_type),
        "length": length,
        "transaction_id": txn,
        "total_bytes": len(payload),
    }


def _parse_quic(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {"type": "quic", "length": len(payload)}
    if payload:
        info["first_byte"] = hex(payload[0])
        info["long_header"] = is_likely_quic_long_header(payload)
    return info


def analyze_pcap(pcap_path: Path, *, limit: int = 50) -> Dict[str, Any]:
    if PcapReader is None:
        raise RuntimeError("scapy not installed")

    packets: List[Dict[str, Any]] = []
    with PcapReader(str(pcap_path)) as reader:
        for i, pkt in enumerate(reader):
            if i >= limit:
                break
            if not pkt.haslayer(UDP):
                continue
            udp = pkt[UDP]
            raw = bytes(udp.payload)
            if not raw:
                continue

            entry: Dict[str, Any] = {
                "index": i,
                "sport": int(udp.sport),
                "dport": int(udp.dport),
                "length": len(raw),
                "hex_preview": raw[:32].hex(),
                "cps": SignatureCollector.format_signature(raw),
            }
            if pkt.haslayer(IP):
                entry["src"] = pkt[IP].src
                entry["dst"] = pkt[IP].dst

            if is_stun_message(raw):
                entry["protocol"] = _parse_stun(raw)
            elif is_likely_quic_long_header(raw) or (raw and raw[0] & 0x80):
                entry["protocol"] = _parse_quic(raw)
            elif udp.dport == 53 or udp.sport == 53:
                entry["protocol"] = _parse_dns(raw)
            else:
                entry["protocol"] = {"type": "udp", "length": len(raw)}

            packets.append(entry)

    return {
        "pcap": str(pcap_path),
        "packet_count": len(packets),
        "packets": packets,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze pcap for I1-I5 workbook")
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args(argv)

    report = analyze_pcap(args.pcap.resolve(), limit=args.limit)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
