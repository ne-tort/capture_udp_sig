"""Capture timeout policy tests."""

from python_signatures.capture_timeouts import get_capture_timeout


def test_default_timeouts():
    assert get_capture_timeout("dns") == 12
    assert get_capture_timeout("dtls") == 18
    assert get_capture_timeout("sip_multi") == 18
    assert get_capture_timeout("stun_browser") == 15
    assert get_capture_timeout("quic_browser") == 30


def test_override():
    assert get_capture_timeout("dns", override=5) == 5
