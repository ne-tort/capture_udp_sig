"""
SIP / DTLS live capture via UDP triggers + tcpdump (signature-lab).
"""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from python_signatures.base import CollectorOptions, SignatureCollector
from python_signatures.capture import CaptureError, capture_udp_payloads_with_trigger
from python_signatures.client_chain import client_session_chain
from python_signatures.docker_capture import capture_iface, local_ip_for_udp
from python_signatures.library_template_collector import LibraryTemplateProfileCollector


def _parse_host_port(cfg: Dict[str, Any], *, default_host: str, default_port: int) -> Tuple[str, int]:
    if isinstance(cfg.get("host"), str) and cfg["host"].strip():
        host = cfg["host"].strip()
        port = int(cfg.get("port", default_port))
        return host, port
    targets = cfg.get("targets") or cfg.get("servers")
    if isinstance(targets, list) and targets:
        raw = str(targets[0]).strip()
        if ":" in raw:
            h, p = raw.rsplit(":", 1)
            return h.strip(), int(p)
        return raw, default_port
    return default_host, default_port


def _parse_sip_servers(cfg: Dict[str, Any]) -> List[Tuple[str, int]]:
    servers = cfg.get("servers")
    if isinstance(servers, list) and servers:
        out: List[Tuple[str, int]] = []
        for raw in servers:
            s = str(raw).strip()
            if ":" in s:
                h, p = s.rsplit(":", 1)
                out.append((h.strip(), int(p)))
            else:
                out.append((s, 5060))
        return out
    host, port = _parse_host_port(cfg, default_host="sip2sip.info", default_port=5060)
    return [(host, port)]


def _sip_options_packet(host: str, *, seq: int = 1) -> bytes:
    branch = f"z9hG4bK-capture-{seq}"
    call_id = f"capture-probe-{seq}@local"
    return (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP capture.local:5060;branch={branch}\r\n"
        f"From: <sip:capture@local>;tag=capture{seq}\r\n"
        f"To: <sip:probe@{host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {seq} OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def _template_collect(options: Any, protocol_name: str) -> List[Dict[str, Any]]:
    tmpl = Path(__file__).resolve().parent / "config" / "profile_templates" / f"{protocol_name}.json"
    tmpl_opts = CollectorOptions(
        config_path=tmpl,
        out_path=options.out_path,
        count=options.count,
        iface=options.iface,
        timeout=options.timeout,
        dry_run=True,
        registry_profile_id=protocol_name,
    )
    return LibraryTemplateProfileCollector(tmpl_opts).collect()


class SipSignatureCollector(SignatureCollector):
    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None) or "sip"
        super().__init__(str(rid).strip(), options)

    def _client_rounds(self, cfg: Dict[str, Any]) -> int:
        if self.protocol_name == "sip_multi":
            return int(cfg.get("client_rounds", 3))
        return int(cfg.get("client_rounds", 1))

    def collect(self) -> List[Dict[str, Any]]:
        if self.options.dry_run:
            return _template_collect(self.options, self.protocol_name)

        cfg = self.load_config()
        servers = _parse_sip_servers(cfg)
        rounds = max(1, min(5, self._client_rounds(cfg)))
        timeout = self.options.timeout or 15
        iface = capture_iface(cfg.get("iface"), self.options.iface)

        best_entry: Dict[str, Any] | None = None
        best_len = 0
        last_err: Exception | None = None

        for host, port in servers:
            try:
                host_ip = socket.gethostbyname(host)
                bpf = f"udp and host {host_ip} and port {port}"
                local_ip = local_ip_for_udp(host_ip, port)

                def trigger(h=host, p=port, n_rounds=rounds) -> None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    try:
                        for seq in range(1, n_rounds + 1):
                            sock.sendto(_sip_options_packet(h, seq=seq), (h, p))
                            try:
                                sock.recvfrom(4096)
                            except OSError:
                                pass
                            time.sleep(0.35)
                    finally:
                        sock.close()

                packets = capture_udp_payloads_with_trigger(
                    bpf, trigger, iface=iface, timeout=timeout, post_trigger_wait=2.5,
                )
                if not packets:
                    continue

                chain = client_session_chain(packets, local_ip, max_slots=5)
                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": f"{host}:{port}",
                    "direction": "client",
                    "hex": self.format_signature(chain[0]),
                    "_bpf": bpf,
                    "_capture_chain_len": len(chain),
                    "_client_rounds": rounds,
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
            msg = f"SIP live capture failed for all servers: {last_err}"
            raise RuntimeError(msg)

        return [best_entry]


class DtlsSignatureCollector(SignatureCollector):
    def __init__(self, options: Any) -> None:
        super().__init__("dtls", options)

    def collect(self) -> List[Dict[str, Any]]:
        if self.options.dry_run:
            return _template_collect(self.options, self.protocol_name)

        cfg = self.load_config()
        host, port = _parse_host_port(cfg, default_host="1.1.1.1", default_port=853)
        timeout = self.options.timeout or 18
        iface = capture_iface(cfg.get("iface"), self.options.iface)
        host_ip = socket.gethostbyname(host) if not host.replace(".", "").isdigit() else host
        bpf = f"udp and host {host_ip} and port {port}"
        local_ip = local_ip_for_udp(host_ip, port)
        sni = str(cfg.get("sni", "one.one.one.one"))
        handshake_wait = int(cfg.get("handshake_wait_sec", 12))

        def trigger() -> None:
            proc = subprocess.Popen(
                [
                    "openssl",
                    "s_client",
                    "-dtls1_2",
                    "-connect",
                    f"{host_ip}:{port}",
                    "-servername",
                    sni,
                    "-brief",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                proc.wait(timeout=handshake_wait)
            except subprocess.TimeoutExpired:
                proc.kill()

        try:
            packets = capture_udp_payloads_with_trigger(
                bpf, trigger, iface=iface, timeout=timeout, post_trigger_wait=3.0,
            )
        except CaptureError as e:
            raise RuntimeError(f"DTLS live capture failed for {host_ip}:{port}: {e}") from e

        if not packets:
            raise RuntimeError(f"DTLS live capture: no UDP packets for {host_ip}:{port}")

        chain = client_session_chain(packets, local_ip, max_slots=5)
        entry: Dict[str, Any] = {
            "protocol": "dtls",
            "target": f"{host_ip}:{port}",
            "direction": "client",
            "hex": self.format_signature(chain[0]),
            "_bpf": bpf,
            "_capture_chain_len": len(chain),
        }
        for sk, pl in zip(("i2", "i3", "i4", "i5"), chain[1:5]):
            entry[sk] = self.format_signature(pl)
        return [entry]
