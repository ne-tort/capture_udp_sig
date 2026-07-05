"""Tests for siglab CLI and library_api panel bridge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_LAB = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_browser(monkeypatch):
    monkeypatch.setenv("CAPTURE_NO_BROWSER", "1")


def test_features_browser_disabled():
    from python_signatures.features import (
        BROWSER_PROFILE_IDS,
        browser_capture_available,
        profile_available,
        unavailable_reason,
    )

    assert browser_capture_available() is False
    assert profile_available("dns") is True
    assert profile_available("quic_browser") is False
    assert unavailable_reason("quic_browser") == "browser capture disabled (CAPTURE_NO_BROWSER)"


def test_list_profiles_meta():
    from python_signatures.library_api import list_profiles_meta

    meta = list_profiles_meta(dry_run=True)
    assert "dns" in meta["all_profile_ids"]
    assert len(meta["profiles"]) == 11
    dns = next(p for p in meta["profiles"] if p["profile_id"] == "dns")
    assert dns["label"] == "DNS"
    assert dns["ready"] is True


def test_siglab_list_json(capsys):
    from siglab.cli import main

    code = main(["--json", "list", "--available-only"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "dns" in payload["profile_ids"]
    assert "quic_browser" not in payload["profile_ids"]


def test_export_panel_partial(tmp_path):
    from python_signatures.export_formats import lab_batch_to_panel, to_panel_entry

    entry = to_panel_entry({"profile_id": "dns", "i1": "<b 0x00>", "i2": "<b 0x01>"})
    panel = lab_batch_to_panel({"profiles": {"dns": entry}})
    assert panel["dns"]["i1"] == "<b 0x00>"


def test_library_invoke_known_ids():
    from python_signatures.library_api import invoke

    ids = invoke("known_profile_ids", available_only=True, dry_run=True)
    assert "dns" in ids


def test_capture_profile_dry_run(tmp_path):
    from python_signatures.library_api import capture_profile

    result = capture_profile("dns", dry_run=True, merge_into_signatures=False)
    assert result["success"] is True
    assert "i1" in result["slots"]


def test_init_signatures_defaults(tmp_path):
    from python_signatures.library_api import init_signatures_defaults

    out = tmp_path / "signatures.json"
    result = init_signatures_defaults(out_path=out)
    assert result["success"] is True
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "dns" in data
