"""
Run all protocol signature collectors.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_signatures.base import CollectorOptions
from python_signatures.browser_quic_collector import BrowserQuicSignatureCollector
from python_signatures.browser_stun_collector import BrowserStunSignatureCollector
from python_signatures.dns_collector import DnsSignatureCollector
from python_signatures.ntp_collector import NtpSignatureCollector
from python_signatures.sip_dtls_collector import DtlsSignatureCollector, SipSignatureCollector
from python_signatures.cps_builder import apply_cps_specs_to_sig
from python_signatures.features import profile_available, unavailable_reason
from python_signatures.profile_cps import merge_collector_output_strict
from python_signatures.slot_policy import get_slot_policy
from python_signatures.template_pool import pick_random_panel_entry

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PROTOCOL_REGISTRY = [
    ("dns", DnsSignatureCollector, "dns_targets.json"),
    ("sip", SipSignatureCollector, "sip_targets.json"),
    ("sip_multi", SipSignatureCollector, "sip_multi_targets.json"),
    ("dtls", DtlsSignatureCollector, "dtls_targets.json"),
    ("ntp", NtpSignatureCollector, "ntp_targets.json"),
    ("quic", BrowserQuicSignatureCollector, "quic_targets.json"),
    ("quic_browser", BrowserQuicSignatureCollector, "quic_browser_targets.json"),
    ("quic_tls_browser", BrowserQuicSignatureCollector, "quic_tls_browser_targets.json"),
    ("stun", BrowserStunSignatureCollector, "stun_targets.json"),
    ("webrtc", BrowserStunSignatureCollector, "webrtc_targets.json"),
    ("stun_browser", BrowserStunSignatureCollector, "stun_browser_targets.json"),
]


def _profile_from_template_pool(profile_id: str) -> Optional[Dict[str, Any]]:
    entry = pick_random_panel_entry(profile_id)
    if not entry or not entry.get("i1"):
        return None
    return {
        **entry,
        "slot_sources": {k: "template_pool" for k in entry},
        "incomplete_slots": [],
    }


def run_all(
    config_dir: Path,
    out_path: Path,
    timeout: int,
    dry_run: bool,
    *,
    strict: bool = False,
    policy_path: Optional[Path] = None,
    available_only: bool = False,
    skip_errors: bool = False,
    use_template_on_failure: bool = True,
) -> Dict[str, Any]:
    profiles: Dict[str, Any] = {}
    skipped: List[str] = []
    any_incomplete = False

    for profile_id, collector_cls, config_rel in PROTOCOL_REGISTRY:
        if available_only and not profile_available(profile_id, dry_run=dry_run):
            reason = unavailable_reason(profile_id) or "unavailable"
            logger.warning("Skipping %s: %s", profile_id, reason)
            skipped.append(profile_id)
            continue
        config_path = config_dir / config_rel
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")

        policy = get_slot_policy(profile_id, policy_path=policy_path)
        required = policy.get("required_slots")

        opts = CollectorOptions(
            config_path=config_path,
            out_path=None,
            count=1,
            timeout=timeout,
            dry_run=dry_run,
            registry_profile_id=profile_id,
        )
        collector = collector_cls(opts)
        try:
            signatures = collector.collect()
        except Exception as e:
            if skip_errors and use_template_on_failure:
                tpl = _profile_from_template_pool(profile_id)
                if tpl:
                    logger.warning("Collector %s failed, using template pool: %s", profile_id, e)
                    profiles[profile_id] = tpl
                    continue
            if skip_errors:
                logger.warning("Collector %s failed (skipped): %s", profile_id, e)
                continue
            logger.exception("Collector %s failed: %s", profile_id, e)
            raise

        if not signatures or not isinstance(signatures[0].get("hex"), str):
            if skip_errors and use_template_on_failure:
                tpl = _profile_from_template_pool(profile_id)
                if tpl:
                    profiles[profile_id] = tpl
                    continue
            raise ValueError(f"Collector {profile_id} returned no valid hex")

        sig = apply_cps_specs_to_sig(profile_id, signatures[0])
        merged = merge_collector_output_strict(
            profile_id,
            sig,
            allow_template_fallback=True,
            required_slots=required,
        )
        profile_out = merged.to_profile_dict()
        profiles[profile_id] = profile_out

        if merged.incomplete_slots:
            any_incomplete = True
            logger.warning(
                "Profile %s incomplete slots: %s",
                profile_id,
                ", ".join(merged.incomplete_slots),
            )

    if strict and any_incomplete:
        raise RuntimeError("strict mode: one or more profiles have incomplete_slots")

    return {
        "_meta": {
            "strict": strict,
            "dry_run": dry_run,
            "skipped_profiles": skipped,
        },
        "profiles": profiles,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run signature collectors.")
    parser.add_argument("--out", required=True)
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--policy", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    out_path = Path(args.out).resolve()
    config_dir = (args.config_dir or Path(__file__).resolve().parent / "config").resolve()
    policy_path = args.policy.resolve() if args.policy else None

    try:
        data = run_all(
            config_dir,
            out_path,
            timeout=args.timeout,
            dry_run=args.dry_run,
            strict=args.strict,
            policy_path=policy_path,
        )
    except Exception:
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Wrote %d profiles to %s", len(data["profiles"]), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
