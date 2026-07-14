"""
CPS helpers retained only for payload formatting tests.
Live capture must NEVER synthesize dynamic tags — defaults are fixed <b 0x...> snapshots.
"""

from __future__ import annotations

from typing import Any, Dict


def apply_cps_specs_to_sig(profile_id: str, sig: Dict[str, Any]) -> Dict[str, Any]:
    """No-op: keep live capture bytes as pure ``<b 0x...>`` snapshots."""
    return dict(sig)
