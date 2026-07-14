"""CPS builder is a no-op for live capture snapshots."""

from python_signatures.cps_builder import apply_cps_specs_to_sig


def test_apply_cps_passthrough():
    raw = {"hex": "<b 0x000100002112a442000000000000000000000000>"}
    out = apply_cps_specs_to_sig("stun", raw)
    assert out["hex"] == raw["hex"]
    assert "_cps_synth_slots" not in out


def test_apply_cps_keeps_pure_b():
    raw = {"hex": "<b 0xca0000000108e9ac8011deadbeef>", "i2": "<b 0xabcd>"}
    out = apply_cps_specs_to_sig("quic_browser", raw)
    assert out == raw or out["hex"] == raw["hex"]
