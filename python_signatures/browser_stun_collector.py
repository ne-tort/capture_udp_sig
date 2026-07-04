"""
STUN Binding via WebRTC in Chromium + tcpdump (signature-lab).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.docker_capture import capture_iface, docker_chromium_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures

try:
    from browser_capture.core.orchestrator import CaptureOrchestrator
except ImportError:
    CaptureOrchestrator = None  # type: ignore[misc, assignment]


def _resolve_stun_url(cfg: Dict[str, Any]) -> str:
    u = cfg.get("stun_url")
    if isinstance(u, str) and u.strip():
        return u.strip()
    servers = cfg.get("servers")
    if isinstance(servers, list) and servers:
        first = str(servers[0]).strip()
        if first.startswith("stun:"):
            return first
        if ":" in first:
            return f"stun:{first}"
        return f"stun:{first}:3478"
    return "stun:stun.l.google.com:19302"


def _stun_server_list(cfg: Dict[str, Any]) -> List[str]:
    servers = cfg.get("servers")
    if isinstance(servers, list) and servers:
        out: List[str] = []
        for s in servers:
            raw = str(s).strip()
            if not raw:
                continue
            if raw.startswith("stun:"):
                out.append(raw)
            elif ":" in raw:
                out.append(f"stun:{raw}")
            else:
                out.append(f"stun:{raw}:3478")
        if out:
            return out
    return [_resolve_stun_url(cfg)]


class BrowserStunSignatureCollector(SignatureCollector):
    """ICE + STUN from real pcap; dry_run uses fixtures."""

    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None)
        if not isinstance(rid, str) or not rid.strip():
            rid = "stun_browser"
        super().__init__(rid.strip(), options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        use_response = cfg.get("use_response", True) is not False
        timeout = self.options.timeout or 15
        iface = capture_iface(cfg.get("iface"), self.options.iface)
        in_docker = os.environ.get("CAPTURE_IN_DOCKER") == "1"
        servers = _stun_server_list(cfg)

        if self.options.dry_run:
            sigs = build_dry_run_signatures(
                self.protocol_name,
                self.protocol_name,
                servers,
                limit=1,
                direction="client",
            )
            return sigs

        if CaptureOrchestrator is None:
            raise RuntimeError("browser_capture not installed")

        orch = CaptureOrchestrator()
        best_entry: Dict[str, Any] | None = None
        best_score = -1
        last_err: Exception | None = None

        for stun_url in servers:
            try:
                extra = docker_chromium_args(stun_url) if in_docker else None
                r = orch.capture_stun_webrtc(
                    stun_url=stun_url,
                    iface=iface,
                    timeout=timeout,
                    extra_chromium_args=extra,
                )
                if not r.outgoing_stun:
                    raise RuntimeError("no outgoing STUN")

                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": stun_url,
                    "direction": "client",
                    "hex": self.format_signature(r.outgoing_stun),
                    "_bpf": r.bpf_filter,
                }
                score = 1
                if use_response and r.incoming_stun:
                    entry["i2"] = self.format_signature(r.incoming_stun)
                    score = 2

                if score > best_score:
                    best_score = score
                    best_entry = entry
                if best_score >= 2:
                    break
            except Exception as e:
                last_err = e
                continue

        if best_entry is None:
            raise RuntimeError(f"Browser STUN capture failed for all servers: {last_err}")

        return [best_entry]


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser("Browser STUN collector (WebRTC ICE + tcpdump)")
    args = parser.parse_args(argv)
    opts = options_from_args(args)
    col = BrowserStunSignatureCollector(opts)
    sigs = col.collect()
    col.save(sigs)
    print(f"Collected {len(sigs)} browser STUN signatures (dry_run={opts.dry_run}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
