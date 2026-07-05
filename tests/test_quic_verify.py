"""QUIC slot verification tests."""

import json
from pathlib import Path

from python_signatures.provenance import export_prod_profile
from python_signatures.quic_verify import parse_pure_b_tag, verify_quic_slots


def _load_live_profile():
    p = Path(__file__).resolve().parent.parent / "output" / "live_quic_browser_debug.json"
    if p.is_file():
        return json.loads(p.read_text())["profile"]
    p2 = Path(__file__).resolve().parent.parent / "output" / "live_quic_browser.json"
    if p2.is_file():
        d = json.loads(p2.read_text())
        return d.get("profile", d)
    return None


def test_parse_pure_b_tag_roundtrip():
    payload = bytes.fromhex("c40000000108" + "ab" * 100)
    cps = f"<b 0x{payload.hex()}>"
    assert parse_pure_b_tag(cps) == payload


def test_quic_tls_print_slot_reports_no_crash():
    from python_signatures.protocol_verify import print_slot_reports, verify_quic_tls_slots
    import io
    import sys

    profile = {
        "i1": "<b 0x16030100aa010000a60303aabbccdd0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f>",
        "i2": "<b 0xc700000001><rc 8><t><r 100>",
    }
    reports = verify_quic_tls_slots(profile)
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        print_slot_reports(reports)
    finally:
        sys.stdout = old
    out = buf.getvalue()
    assert "I1" in out
    assert "quic" in out.lower() or "tls" in out.lower()


def test_parse_rejects_hybrid_cps():
    assert parse_pure_b_tag("<b 0x01><rc 8><t>") is None


def test_verify_live_capture_if_present():
    profile = _load_live_profile()
    if profile is None:
        return
    reports = verify_quic_slots(profile)
    i1 = next(r for r in reports if r.slot == "i1")
    assert i1.ok
    assert i1.byte_len >= 100
    assert i1.hex_nibbles == i1.byte_len * 2
    assert i1.quic_version == 1
    assert i1.packet_type == "initial"


def test_export_prod_omits_missing():
    prod = export_prod_profile({"i1": "<b 0x01>", "slot_sources": {"i2": "missing"}}, profile_id="quic_browser")
    assert prod == {"profile_id": "quic_browser", "i1": "<b 0x01>"}


def test_partial_slots_ok_for_policy():
    from python_signatures.profile_cps import merge_collector_output_strict

    mr = merge_collector_output_strict(
        "quic_browser",
        {"hex": "<b 0x01>", "i2": "<b 0x02>"},
        allow_template_fallback=False,
        required_slots=["i1"],
    )
    assert mr.incomplete_slots == []
    assert "i3" not in mr.to_profile_dict() or mr.i3 is None
