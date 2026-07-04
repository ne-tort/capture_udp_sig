#!/usr/bin/env python3
from browser_capture.core.orchestrator import CaptureOrchestrator

o = CaptureOrchestrator()
try:
    r = o.capture_quic_http3("https://cloudflare-quic.com/", iface="any", timeout=45)
    chain = r.quic_packet_chain or []
    print(f"ok chain={len(chain)} outgoing={len(r.outgoing)} all_udp={len(r.all_udp)} bpf={r.bpf_filter}")
except Exception as e:
    print(f"ERR {type(e).__name__}: {e}")
