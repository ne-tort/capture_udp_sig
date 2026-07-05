"""Tests for unified signature bank load/save/resume."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from python_signatures.signature_bank import (
    append_entry,
    entry_from_prod,
    is_duplicate_i1,
    load_bank,
    next_iteration,
    parse_rate_limit_wait,
    profile_count,
    save_bank,
)


def test_empty_bank_roundtrip(tmp_path: Path):
    path = tmp_path / "bank.json"
    bank = load_bank(path, default_target=1000)
    assert bank["target"] == 1000
    assert bank["profiles"] == {}

    append_entry(bank, "dns", 1, {"i1": "<b 0x01>", "i2": "<b 0x02>"})
    save_bank(path, bank)

    loaded = load_bank(path)
    assert profile_count(loaded, "dns") == 1
    assert loaded["profiles"]["dns"]["1"]["i1"] == "<b 0x01>"


def test_resume_next_iteration(tmp_path: Path):
    bank = load_bank(tmp_path / "x.json", default_target=5)
    append_entry(bank, "sip", 1, {"i1": "<b 0xaa>"})
    append_entry(bank, "sip", 3, {"i1": "<b 0xbb>"})
    assert profile_count(bank, "sip") == 2
    assert next_iteration(bank, "sip") == 4


def test_no_dates_in_entries(tmp_path: Path):
    bank = load_bank(tmp_path / "x.json")
    append_entry(bank, "dns", 1, {"i1": "<b 0x01>"})
    raw = json.dumps(bank)
    assert "captured_at" not in raw
    assert "date" not in raw.lower() or "update" not in raw.lower()


def test_duplicate_i1_detection():
    bank = load_bank(Path("/nonexistent"), default_target=10)
    append_entry(bank, "dns", 1, {"i1": "<b 0xdead>"})
    assert is_duplicate_i1(bank, "dns", {"i1": "<b 0xdead>"})
    assert not is_duplicate_i1(bank, "dns", {"i1": "<b 0xbeef>"})


def test_rate_limit_parsing():
    is_rl, wait = parse_rate_limit_wait("HTTP 429 Too Many Requests", attempt=1)
    assert is_rl
    assert wait >= 15

    is_rl2, wait2 = parse_rate_limit_wait("retry-after: 45", attempt=2)
    assert is_rl2
    assert wait2 >= 45

    is_rl3, _ = parse_rate_limit_wait("no packets captured", attempt=1)
    assert not is_rl3


def test_entry_from_prod():
    prod = {"profile_id": "dns", "ok": True, "i1": "<b 0x01>", "i3": "<b 0x03>"}
    entry = entry_from_prod(prod)
    assert entry == {"i1": "<b 0x01>", "i3": "<b 0x03>"}
    assert "profile_id" not in entry
    assert "ok" not in entry


def test_atomic_save_survives_reload(tmp_path: Path):
    path = tmp_path / "bank.json"
    bank = load_bank(path, default_target=3)
    for i in range(1, 4):
        append_entry(bank, "ntp", i, {"i1": f"<b 0x{i:02x}>"})
        save_bank(path, bank)
    assert profile_count(load_bank(path), "ntp") == 3
