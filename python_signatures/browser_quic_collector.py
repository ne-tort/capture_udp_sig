"""
QUIC/HTTP3 capture via Chromium (Playwright) + tcpdump.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.docker_capture import capture_iface, docker_chromium_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures

try:
    from browser_capture.core.models import QuicTlsCaptureResult
    from browser_capture.core.orchestrator import CaptureOrchestrator
except ImportError:
    CaptureOrchestrator = None  # type: ignore[misc, assignment]
    QuicTlsCaptureResult = None  # type: ignore[misc, assignment]


class BrowserQuicSignatureCollector(SignatureCollector):
    """Chromium + tcpdump -> QUIC chain (up to 5 UDP payloads)."""

    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None)
        if not isinstance(rid, str) or not rid.strip():
            rid = "quic_browser"
        super().__init__(rid.strip(), options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        urls = cfg.get("urls") or []
        if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
            raise RuntimeError('Config must contain "urls": ["https://example.com/", ...].')

        limit = self.options.count or 1
        timeout = self.options.timeout or 60
        iface = capture_iface(cfg.get("iface"), self.options.iface)
        split_coalesced = bool(cfg.get("split_coalesced", False))
        https_quic_tcp = bool(cfg.get("https_quic_tcp", False))
        tls_clienthello_as_i1 = bool(cfg.get("tls_clienthello_as_i1", False))
        in_docker = os.environ.get("CAPTURE_IN_DOCKER") == "1"

        if self.options.dry_run:
            sigs = build_dry_run_signatures(
                self.protocol_name, self.protocol_name, urls, limit=limit, direction="client",
            )
            return [apply_cps_specs_to_sig(self.protocol_name, s) for s in sigs]

        if CaptureOrchestrator is None:
            raise RuntimeError("browser_capture not installed")

        orch = CaptureOrchestrator()
        best_entry: Dict[str, Any] | None = None
        best_chain_len = 0
        last_err: Exception | None = None

        for url in urls:
            if best_chain_len >= 5:
                break
            try:
                extra = docker_chromium_args(url) if in_docker else None
                if https_quic_tcp:
                    r = orch.capture_https_quic_and_tcp(
                        url, iface=iface, timeout=timeout,
                        split_coalesced=split_coalesced, extra_chromium_args=extra,
                    )
                else:
                    r = orch.capture_quic_http3(
                        url, iface=iface, timeout=timeout,
                        split_coalesced=split_coalesced, extra_chromium_args=extra,
                    )
                chain = list(r.quic_packet_chain) if r.quic_packet_chain else list(r.quic_initial_candidates)
                if tls_clienthello_as_i1:
                    tcp_pl = getattr(r, "first_outgoing_tcp_payload", None)
                    if not tcp_pl:
                        raise RuntimeError("tls_clienthello_as_i1: no outgoing TCP payload")
                    if not chain:
                        raise RuntimeError("tls_clienthello_as_i1: empty QUIC chain")
                    entry = {
                        "protocol": self.protocol_name,
                        "target": url,
                        "direction": "client",
                        "hex": self.format_signature(tcp_pl),
                        "_i1_transport": "tcp_tls_clienthello",
                    }
                    for sk, pkt in zip(("i2", "i3", "i4", "i5"), chain[:4]):
                        entry[sk] = self.format_signature(pkt)
                else:
                    if not chain:
                        raise RuntimeError("empty QUIC chain")
                    entry = {
                        "protocol": self.protocol_name,
                        "target": url,
                        "direction": "client",
                        "hex": self.format_signature(chain[0]),
                    }
                    for sk, pkt in zip(("i2", "i3", "i4", "i5"), chain[1:5]):
                        entry[sk] = self.format_signature(pkt)
                effective_len = (1 + min(4, len(chain))) if tls_clienthello_as_i1 else len(chain)
                entry["_capture_chain_len"] = effective_len
                entry["_bpf"] = r.bpf_filter
                entry["_outgoing_udp"] = len(r.outgoing)

                if effective_len > best_chain_len:
                    best_chain_len = effective_len
                    best_entry = apply_cps_specs_to_sig(self.protocol_name, entry)
            except Exception as e:
                last_err = e
                continue

        if best_entry is None:
            msg = f"Browser QUIC capture failed for all URLs: {last_err}"
            raise RuntimeError(msg)

        return [best_entry]


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser("Browser QUIC collector")
    args = parser.parse_args(argv)
    col = BrowserQuicSignatureCollector(options_from_args(args))
    col.save(col.collect())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
