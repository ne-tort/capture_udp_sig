"""Strict merge tests (signature-lab)."""

from python_signatures.profile_cps import merge_collector_output_strict


def test_quic_partial_required_i1_only():
    mr = merge_collector_output_strict(
        "quic_browser",
        {"hex": "<b 0x01>", "i2": "<b 0x02>"},
        allow_architect=False,
        required_slots=["i1"],
    )
    assert mr.incomplete_slots == []
    assert mr.slot_sources["i3"] == "missing"


def test_strict_no_architect_incomplete():
    mr = merge_collector_output_strict(
        "quic_browser",
        {"hex": "<b 0x01>", "i2": "<b 0x02>"},
        allow_architect=False,
        required_slots=["i1", "i2", "i3", "i4", "i5"],
    )
    assert mr.i1 == "<b 0x01>"
    assert mr.i2 == "<b 0x02>"
    assert "i3" in mr.incomplete_slots
    assert mr.slot_sources["i3"] == "missing"
    assert "architect" not in mr.slot_sources.values()


def test_strict_with_architect_fills():
    mr = merge_collector_output_strict(
        "quic_browser",
        {"hex": "<b 0x01>"},
        allow_architect=True,
    )
    assert mr.i2 and mr.i5
    assert mr.slot_sources["i3"] == "architect"
    assert mr.incomplete_slots == []


def test_stun_policy_optional_slots():
    mr = merge_collector_output_strict(
        "stun_browser",
        {"hex": "<b 0x000100002112a442000000000000000000000000>"},
        allow_architect=False,
        required_slots=["i1"],
    )
    assert mr.incomplete_slots == []


def test_full_fixture_no_architect():
    sig = {
        "hex": "<b 0x01>",
        "i2": "<b 0x02>",
        "i3": "<b 0x03>",
        "i4": "<b 0x04>",
        "i5": "<b 0x05>",
    }
    mr = merge_collector_output_strict("quic_browser", sig, allow_architect=False)
    assert mr.incomplete_slots == []
    assert all(v == "capture" for k, v in mr.slot_sources.items() if k != "i1" or v)
