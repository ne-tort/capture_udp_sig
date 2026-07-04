"""Tests for client-initiated session chain builder."""

from python_signatures.client_chain import client_session_chain

LOCAL = "10.0.0.2"
REMOTE = "8.8.8.8"


def _pkt(payload: bytes, src: str, dst: str) -> tuple:
    return (payload, src, 9000, dst, 53)


def test_client_session_chain_out_in_out():
    packets = [
        _pkt(b"q1", LOCAL, REMOTE),
        _pkt(b"r1", REMOTE, LOCAL),
        _pkt(b"q2", LOCAL, REMOTE),
    ]
    chain = client_session_chain(packets, LOCAL, max_slots=3)
    assert chain == [b"q1", b"r1", b"q2"]


def test_never_starts_with_server():
    packets = [
        _pkt(b"r0", REMOTE, LOCAL),
        _pkt(b"q1", LOCAL, REMOTE),
    ]
    chain = client_session_chain(packets, LOCAL, max_slots=2)
    assert chain[0] == b"q1"
