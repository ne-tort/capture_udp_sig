"""
Provenance tracking and CPS validation for signature-lab.

Classifies each I1-I5 slot as capture, template_hex, architect, cps_synth, or missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

from python_signatures.architect_fallbacks import ARCHITECT_DEFAULTS

SlotSource = Literal["capture", "template_hex", "architect", "cps_synth", "missing"]

SLOT_KEYS = ("i1", "i2", "i3", "i4", "i5")
CAPTURE_KEYS = ("hex", "i2", "i3", "i4", "i5")

COLLECTOR_KIND: Dict[str, str] = {
    "dns": "template",
    "sip": "template",
    "dtls": "template",
    "quic": "browser_quic",
    "quic_browser": "browser_quic",
    "stun": "browser_stun",
    "webrtc": "browser_stun",
    "stun_browser": "browser_stun",
}

_TAG_RE = re.compile(
    r"<b\s+0x([0-9a-fA-F]*)>|<r\s+(\d+)>|<rc\s+(\d+)>|<rd\s+(\d+)>|<t>|"
    r"<c>|<c\s+[^>]+>",
    re.IGNORECASE,
)


@dataclass
class CpsIssue:
    severity: Literal["error", "warn", "info"]
    code: str
    message: str


@dataclass
class SlotDiff:
    slot: str
    capture_value: Optional[str]
    architect_value: str
    same: bool
    structural_note: str = ""


def capture_key_for_slot(slot: str) -> str:
    return "hex" if slot == "i1" else slot


def raw_capture_value(sig: Dict[str, Any], slot: str) -> Optional[str]:
    key = capture_key_for_slot(slot)
    v = sig.get(key)
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def classify_slot(
    profile_id: str,
    sig: Dict[str, Any],
    slot: str,
    *,
    merged_value: Optional[str] = None,
    allow_architect: bool = False,
) -> SlotSource:
    """Classify provenance for one slot given raw collector sig."""
    kind = COLLECTOR_KIND.get(profile_id, "unknown")
    raw = raw_capture_value(sig, slot)

    synth = sig.get("_cps_synth_slots")
    if isinstance(synth, list) and slot in synth:
        return "cps_synth"

    if raw:
        if kind == "template":
            return "template_hex"
        return "capture"

    if merged_value and allow_architect:
        arch = ARCHITECT_DEFAULTS.get(profile_id, {}).get(slot, "")
        if merged_value == arch:
            return "architect"

    return "missing"


def static_hex_byte_len(cps: str) -> Optional[int]:
    total = 0
    for m in re.finditer(r"<b\s+0x([0-9a-fA-F]*)>", cps, re.IGNORECASE):
        hx = m.group(1)
        if hx:
            total += len(hx) // 2
    return total if total else None


def validate_cps(cps: str, *, slot: str) -> List[CpsIssue]:
    issues: List[CpsIssue] = []
    if not cps or not cps.strip():
        issues.append(CpsIssue("error", "empty_cps", f"{slot}: empty CPS string"))
        return issues

    pos = 0
    while pos < len(cps):
        m = _TAG_RE.match(cps, pos)
        if not m:
            rest = cps[pos : pos + 40]
            issues.append(CpsIssue("error", "unknown_tag", f"{slot}: unknown fragment near {rest!r}"))
            break
        if m.group(0).lower().startswith("<c"):
            issues.append(CpsIssue("error", "unsupported_c_tag", f"{slot}: <c> not supported by amneziawg-go"))
        if m.group(1) is not None:
            hx = m.group(1)
            if len(hx) % 2 != 0:
                issues.append(CpsIssue("error", "odd_hex", f"{slot}: <b 0x> odd hex length ({len(hx)} nibbles)"))
            if not hx:
                issues.append(CpsIssue("warn", "empty_b_tag", f"{slot}: empty <b 0x>"))
        for gi, name, limit in ((2, "r", 1000), (3, "rc", 1000), (4, "rd", 1000)):
            if m.group(gi) is not None:
                n = int(m.group(gi))
                if n > limit:
                    issues.append(CpsIssue("warn", f"{name}_oversize", f"{slot}: <{name} {n}> > {limit}"))
                if n == 0:
                    issues.append(CpsIssue("warn", f"{name}_zero", f"{slot}: <{name} 0> empty block"))
        pos = m.end()

    if "<t>" not in cps and slot in ("i2", "i3", "i4", "i5"):
        issues.append(CpsIssue("info", "no_timestamp", f"{slot}: no <t> tag"))

    return issues


def compare_with_architect(profile_id: str, merged: Dict[str, str]) -> List[SlotDiff]:
    arch = ARCHITECT_DEFAULTS.get(profile_id, {})
    diffs: List[SlotDiff] = []
    for slot in SLOT_KEYS:
        cap_val = merged.get(slot)
        arch_val = arch.get(slot, "")
        same = cap_val == arch_val if cap_val else False
        note = ""
        if cap_val and arch_val and not same:
            cap_b = static_hex_byte_len(cap_val) or 0
            arch_b = static_hex_byte_len(arch_val) or 0
            if cap_b and arch_b:
                note = f"static_hex_bytes capture={cap_b} architect={arch_b}"
            if "<t>" in arch_val and "<t>" not in (cap_val or ""):
                note = (note + "; architect has <t>, capture does not").strip("; ")
        diffs.append(
            SlotDiff(
                slot=slot,
                capture_value=cap_val,
                architect_value=arch_val,
                same=same,
                structural_note=note,
            )
        )
    return diffs


def export_for_panel(profile: Dict[str, Any]) -> List[str]:
    """
    Emit I1-I5 lines for .conf — only non-empty slots (never ``I3=`` empty).
    """
    lines: List[str] = []
    for slot in SLOT_KEYS:
        val = profile.get(slot)
        if isinstance(val, str) and val.strip():
            lines.append(f"{slot.upper()} = {val.strip()}")
    return lines


def export_prod_profile(profile: Dict[str, Any], *, profile_id: str) -> Dict[str, str]:
    """
    Prod JSON: only filled I slots, no provenance / incomplete metadata.
    """
    out: Dict[str, str] = {"profile_id": profile_id}
    for slot in SLOT_KEYS:
        val = profile.get(slot)
        if isinstance(val, str) and val.strip():
            out[slot] = val.strip()
    return out
