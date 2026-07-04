"""CPS validation and export tests."""

from python_signatures.provenance import export_for_panel, validate_cps


def test_validate_cps_ok():
    issues = validate_cps("<b 0xdeadbeef><r 10><t>", slot="i1")
    assert not [i for i in issues if i.severity == "error"]


def test_validate_cps_rejects_c_tag():
    issues = validate_cps("<b 0x01><c>", slot="i1")
    assert any(i.code == "unsupported_c_tag" for i in issues)


def test_export_omits_empty():
    lines = export_for_panel({"i1": "<b 0x01>", "i3": "<b 0x03>"})
    assert lines == ["I1 = <b 0x01>", "I3 = <b 0x03>"]
    assert not any(l.startswith("I2") for l in lines)
