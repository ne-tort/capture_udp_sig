"""
NTP (UDP mode 3 client) live capture via socket trigger + tcpdump.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from python_signatures.base import CollectorOptions, SignatureCollector
from python_signatures.capture import CaptureError, capture_udp_payloads_with_trigger
from python_signatures.client_chain import client_session_chain
from python_signatures.docker_capture import capture_iface, local_ip_for_udp
from python_signatures.library_template_collector import LibraryTemplateProfileCollector


def _ntp_mode3_request() -> bytes:
    # RFC 5905: 48-byte NTP packet; LI=0, VN=3, Mode=3 (client)
    return b"\x1b" + (b"\x00" * 47)


def _parse_servers(cfg: Dict[str, Any]) -> List[Tuple[str, int]]:
    servers = cfg.get("servers") or cfg.get("targets")
    if isinstance(servers, list) and servers:
        out: List[Tuple[str, int]] = []
        for raw in servers:
            s = str(raw).strip()
            if ":" in s:
                h, p = s.rsplit(":", 1)
                out.append((h.strip(), int(p)))
            else:
                out.append((s, 123))
        return out
    return [("time.google.com", 123), ("pool.ntp.org", 123)]


class NtpSignatureCollector(SignatureCollector):
    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None) or "ntp"
        super().__init__(str(rid).strip(), options)

    def collect(self) -> List[Dict[str, Any]]:
        if self.options.dry_run:
            tmpl = Path(__file__).resolve().parent / "config" / "profile_templates" / "ntp.json"
            tmpl_opts = CollectorOptions(
                config_path=tmpl,
                out_path=self.options.out_path,
                count=self.options.count,
                iface=self.options.iface,
                timeout=self.options.timeout,
                dry_run=True,
                registry_profile_id="ntp",
            )
            return LibraryTemplateProfileCollector(tmpl_opts).collect()

        cfg = self.load_config()
        servers = _parse_servers(cfg)
        # Two client polls → I1 out, I2 in, I3 out (fits max_slots=3, all client-started).
        polls = max(1, min(3, int(cfg.get("client_polls", 2))))
        timeout = self.options.timeout or 10
        iface = capture_iface(cfg.get("iface"), self.options.iface)

        best_entry: Dict[str, Any] | None = None
        best_len = 0
        last_err: Exception | None = None

        for host, port in servers:
            try:
                host_ip = socket.gethostbyname(host)
                bpf = f"udp and host {host_ip} and port {port}"
                local_ip = local_ip_for_udp(host_ip, port)

                def trigger(h=host_ip, p=port, n_polls=polls) -> None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    try:
                        for _ in range(n_polls):
                            sock.sendto(_ntp_mode3_request(), (h, p))
                            try:
                                sock.recvfrom(512)
                            except OSError:
                                pass
                            time.sleep(0.35)
                    finally:
                        sock.close()

                packets = capture_udp_payloads_with_trigger(
                    bpf, trigger, iface=iface, timeout=timeout, post_trigger_wait=2.0,
                )
                if not packets:
                    continue

                chain = client_session_chain(packets, local_ip, max_slots=3)
                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": f"{host}:{port}",
                    "direction": "client",
                    "hex": self.format_signature(chain[0]),
                    "_capture_chain_len": len(chain),
                    "_client_polls": polls,
                }
                for sk, pl in zip(("i2", "i3", "i4", "i5"), chain[1:5]):
                    entry[sk] = self.format_signature(pl)
                if len(chain) > best_len:
                    best_len = len(chain)
                    best_entry = entry
            except Exception as e:
                last_err = e
                continue

        if best_entry is None:
            raise RuntimeError(f"NTP capture failed for all servers: {last_err}")

        return [best_entry]
