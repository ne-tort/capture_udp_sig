"""
DNS signature collector: template (dry-run) or live dig + tcpdump (signature-lab).
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from python_signatures.base import CollectorOptions, SignatureCollector, build_arg_parser, options_from_args
from python_signatures.capture import CaptureError, capture_udp_payloads_with_trigger
from python_signatures.docker_capture import capture_iface
from python_signatures.library_template_collector import LibraryTemplateProfileCollector


def _is_dns_query(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    flags = int.from_bytes(payload[2:4], "big")
    return not bool(flags & 0x8000)


def _is_dns_response(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    flags = int.from_bytes(payload[2:4], "big")
    return bool(flags & 0x8000)


def _parse_queries(cfg: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return (domain, record_type) pairs — mix A/AAAA for distinct responses."""
    raw = cfg.get("queries")
    if isinstance(raw, list) and raw:
        out: List[Tuple[str, str]] = []
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                out.append((str(item["name"]), str(item.get("type", "A")).upper()))
            elif isinstance(item, str):
                out.append((item, "A"))
        return out[:8]
    domains = cfg.get("domains") or ["ya.ru"]
    types = cfg.get("query_types") or []
    out = []
    for i, domain in enumerate(domains[:8]):
        qtype = types[i] if i < len(types) else ("AAAA" if i % 2 else "A")
        out.append((str(domain), str(qtype).upper()))
    return out


class DnsSignatureCollector(SignatureCollector):
    """DNS: library template when dry-run; live capture via dig + tcpdump otherwise."""

    def __init__(self, options: Any) -> None:
        super().__init__("dns", options)

    def collect(self) -> List[Dict[str, Any]]:
        if self.options.dry_run:
            tmpl_path = Path(__file__).resolve().parent / "config" / "profile_templates" / "dns.json"
            tmpl_opts = CollectorOptions(
                config_path=tmpl_path,
                out_path=self.options.out_path,
                count=self.options.count,
                iface=self.options.iface,
                timeout=self.options.timeout,
                dry_run=True,
                registry_profile_id="dns",
            )
            return LibraryTemplateProfileCollector(tmpl_opts).collect()

        cfg = self.load_config()
        queries = _parse_queries(cfg)
        if not queries:
            raise RuntimeError('dns config needs "domains" or "queries"')

        resolver = str(cfg.get("resolver", "8.8.8.8"))
        timeout = self.options.timeout or 12
        iface = capture_iface(cfg.get("iface"), self.options.iface)
        bpf = f"udp and host {resolver} and port 53"
        post_wait = float(cfg.get("post_trigger_wait", 3.0))

        def trigger() -> None:
            for domain, qtype in queries:
                subprocess.run(
                    ["dig", f"@{resolver}", domain, qtype, "+time=2", "+tries=1", "+nocookie"],
                    check=False,
                    capture_output=True,
                )
                time.sleep(0.25)

        try:
            packets = capture_udp_payloads_with_trigger(
                bpf,
                trigger,
                iface=iface,
                timeout=timeout,
                post_trigger_wait=post_wait,
            )
        except CaptureError as e:
            raise RuntimeError(f"DNS live capture failed: {e}") from e

        query_packets = [p for p in packets if _is_dns_query(p[0])]
        response_packets = [p for p in packets if _is_dns_response(p[0])]

        if not query_packets:
            raise RuntimeError("No DNS query captured")

        entry: Dict[str, Any] = {
            "protocol": "dns",
            "target": queries[0][0],
            "direction": "client",
            "hex": self.format_signature(query_packets[0][0]),
            "_bpf": bpf,
            "_resolver": resolver,
            "_query_count": len(queries),
        }
        seen: set[bytes] = set()
        unique_responses: List[bytes] = []
        for resp in response_packets:
            pl = resp[0]
            if pl not in seen:
                seen.add(pl)
                unique_responses.append(pl)
        for sk, pl in zip(("i2", "i3", "i4", "i5"), unique_responses[:4]):
            entry[sk] = self.format_signature(pl)
        entry["_capture_chain_len"] = 1 + min(4, len(unique_responses))
        return [entry]


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser("DNS collector (template or live dig+tcpdump)")
    args = parser.parse_args(argv)
    col = DnsSignatureCollector(options_from_args(args))
    col.save(col.collect())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
