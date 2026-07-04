"""CPS builder tests."""

from python_signatures.cps_builder import apply_cps_specs_to_sig, payload_to_cps, FieldSpec, FieldKind


def test_stun_transaction_id_randomized():
    # STUN Binding Request minimal 20 bytes
    payload = bytes.fromhex("000100002112a442") + b"\x00" * 12
    fields = [
        FieldSpec(0, 8, FieldKind.STATIC),
        FieldSpec(8, 12, FieldKind.RANDOM_BYTES),
    ]
    cps = payload_to_cps(payload, fields)
    assert cps.startswith("<b 0x000100002112a442>")
    assert "<r 12>" in cps


def test_apply_cps_specs_stun_browser():
    raw = {
        "hex": "<b 0x000100002112a44200000000000000000000000000000000>",
    }
    out = apply_cps_specs_to_sig("stun_browser", raw)
    assert "<r 12>" in out["hex"]
    assert "i1" in out.get("_cps_synth_slots", [])


def test_apply_cps_skips_hybrid_cps():
    raw = {"hex": "<b 0xca0000000108e9ac8011><rc 8><t><r 100>"}
    out = apply_cps_specs_to_sig("quic_browser", raw)
    assert out["hex"] == raw["hex"]
    assert "_cps_synth_slots" not in out
