"""Build I-slot chains from client-initiated UDP/TCP sessions (out → in → out …)."""

from __future__ import annotations

from typing import List, Tuple

UdpPacket = Tuple[bytes, str, int, str, int]


def client_session_chain(
    packets: List[UdpPacket],
    local_ip: str,
    *,
    max_slots: int = 5,
) -> List[bytes]:
    """
    Alternate client outbound and server inbound flights.

    I1 must be first client packet; I2+ only follow prior client sends (responses
    or next client round). Never starts with server traffic.
    """
    outbound = [p[0] for p in packets if p[1] == local_ip]
    inbound = [p[0] for p in packets if p[3] == local_ip]
    if not outbound:
        return [p[0] for p in packets[:max_slots]]

    chain: List[bytes] = []
    for i in range(max(len(outbound), len(inbound))):
        if i < len(outbound):
            chain.append(outbound[i])
            if len(chain) >= max_slots:
                break
        if i < len(inbound):
            chain.append(inbound[i])
            if len(chain) >= max_slots:
                break
    return chain[:max_slots]
