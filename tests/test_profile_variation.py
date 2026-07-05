"""Tests for profile variation limits and bank status."""

from __future__ import annotations

from pathlib import Path

from python_signatures.profile_variation import effective_target, profile_variation
from python_signatures.signature_bank import (
    append_entry,
    is_rate_limited,
    is_transient_error,
    load_bank,
    save_bank,
    set_profile_status,
    get_profile_status,
)


def test_effective_target_static_vs_variable():
    assert effective_target("dns", 1000) == 1000
    assert effective_target("sip", 1000) == 1
    assert effective_target("quic_browser", 10) == 1


def test_profile_variation_kinds():
    assert profile_variation("dns")["kind"] == "variable"
    assert profile_variation("ntp")["kind"] == "static"
    assert profile_variation("quic_tls_browser")["max_useful"] == 1


def test_rate_limit_not_transient():
    assert is_rate_limited("HTTP 429 Too Many Requests")
    assert not is_transient_error("HTTP 429 Too Many Requests")


def test_profile_status_roundtrip(tmp_path: Path):
    bank = load_bank(tmp_path / "b.json")
    set_profile_status(bank, "sip", status="static", note="fixed template", effective_target=1)
    save_bank(tmp_path / "b.json", bank)
    loaded = load_bank(tmp_path / "b.json")
    st = get_profile_status(loaded, "sip")
    assert st["status"] == "static"
    assert st["effective_target"] == 1


def test_static_dup_status(tmp_path: Path):
    bank = load_bank(tmp_path / "b.json")
    append_entry(bank, "sip", 1, {"i1": "<b 0xaa>"})
    set_profile_status(bank, "sip", status="static_dup", note="dup", effective_target=1)
    save_bank(tmp_path / "b.json", bank)
    loaded = load_bank(tmp_path / "b.json")
    assert get_profile_status(loaded, "sip")["status"] == "static_dup"
