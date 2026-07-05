"""Tests for strict merge and template pool fallback."""

from __future__ import annotations

import pytest

from python_signatures.profile_cps import merge_collector_output_strict


def _sig(hex_val: str, **extra):
    return {"hex": hex_val, **extra}


def test_strict_no_template_incomplete():
    mr = merge_collector_output_strict(
        "dns",
        _sig("<b 0x0102030405060708090a0b0c0d0e0f101112131415>"),
        allow_template_fallback=False,
    )
    assert mr.i1
    assert mr.incomplete_slots
    assert "architect" not in mr.slot_sources.values()
    assert "template_pool" not in mr.slot_sources.values()


def test_strict_with_template_fills(monkeypatch):
    monkeypatch.setattr(
        "python_signatures.template_pool.pick_random_entry",
        lambda pid: {"i1": "<b 0x01>", "i2": "<b 0x02>", "i3": "<b 0x03>", "i4": "<b 0x04>", "i5": "<b 0x05>"},
    )
    mr = merge_collector_output_strict(
        "dns",
        _sig("<b 0x0102030405060708090a0b0c0d0e0f101112131415>"),
        allow_template_fallback=True,
    )
    assert mr.slot_sources.get("i3") == "template_pool"
    assert not mr.incomplete_slots


def test_full_fixture_no_template_pool():
    from python_signatures.dry_run_fixtures import load_dry_run_fixture

    sig = load_dry_run_fixture("quic_browser")
    mr = merge_collector_output_strict("quic_browser", sig, allow_template_fallback=False)
    assert mr.i1
    assert "template_pool" not in mr.slot_sources.values()
