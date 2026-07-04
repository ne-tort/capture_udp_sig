"""Tests for siglab CLI and library_api panel bridge."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_LAB = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_browser(monkeypatch):
    monkeypatch.setenv("SIGLAB_NO_BROWSER", "1")


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
    assert "dns" not in BROWSER_PROFILE_IDS


def test_list_profiles_meta_dry_run():
    from python_signatures.library_api import list_profiles_meta

    meta = list_profiles_meta(dry_run=True)
    assert "profile_ids" in meta
    assert "dns" in meta["all_profile_ids"]
    assert meta["browser_enabled"] is False


def test_siglab_list_json(capsys):
    from siglab.cli import main

    code = main(["--json", "list", "--available-only"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "dns" in payload["profile_ids"]
    assert "quic_browser" not in payload["profile_ids"]


def test_siglab_capabilities(capsys):
    from siglab.cli import main

    code = main(["--json", "capabilities"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {p["profile_id"]: p for p in payload["profiles"]}
    assert by_id["dns"]["available"] is True
    assert by_id["quic_browser"]["available"] is False


def test_export_panel_partial(tmp_path):
    from python_signatures.export_formats import lab_batch_to_panel, to_panel_entry

    entry = to_panel_entry({"profile_id": "dns", "i1": "<b 0x00>", "i2": "<b 0x01>"})
    assert entry == {"i1": "<b 0x00>", "i2": "<b 0x01>"}
    panel = lab_batch_to_panel({"profiles": {"dns": entry, "sip": {"i1": "x"}}})
    assert panel["dns"]["i1"] == "<b 0x00>"
    assert "sip" in panel


def test_library_invoke_known_ids():
    from python_signatures.library_api import invoke

    ids = invoke("known_profile_ids", available_only=True, dry_run=True)
    assert isinstance(ids, list)
    assert "dns" in ids


def test_capture_profile_dry_run(tmp_path):
    from python_signatures.library_api import capture_profile

    out = tmp_path / "dns.json"
    result = capture_profile("dns", out_path=out, dry_run=True)
    assert result["success"] is True
    assert "i1" in result["slots"]
    assert out.is_file()


def test_regenerate_signatures_dry_run(tmp_path):
    from python_signatures.library_api import regenerate_signatures

    out = tmp_path / "signatures.json"
    cfg = _LAB / "python_signatures" / "config"
    result = regenerate_signatures(
        out_path=out,
        config_dir=cfg,
        dry_run=True,
        panel_format=True,
        available_only=True,
    )
    assert result["success"] is True
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "dns" in data
