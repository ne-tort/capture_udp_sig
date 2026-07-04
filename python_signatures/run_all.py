"""
Run all protocol signature collectors (signature-lab).

Default: strict merge — no Architect fallback. Use --allow-architect-fallback to compare.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_signatures.architect_fallbacks import ARCHITECT_BUNDLE_DATE, ARCHITECT_BUNDLE_VERSION
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


def run_all(
    config_dir: Path,
    out_path: Path,
    timeout: int,
    dry_run: bool,
    *,
    allow_architect_fallback: bool = False,
    strict: bool = False,
    policy_path: Optional[Path] = None,
    available_only: bool = False,
    skip_errors: bool = False,
) -> Dict[str, Any]:
    """
    Run each collector; output profile_id -> { i1..i5, slot_sources, incomplete_slots }.
    """
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
            allow_architect_fallback=allow_architect_fallback,
        )
        collector = collector_cls(opts)
        try:
            signatures = collector.collect()
        except Exception as e:
            if skip_errors:
                logger.warning("Collector %s failed (skipped): %s", profile_id, e)
                continue
            logger.exception("Collector %s failed: %s", profile_id, e)
            raise

        if not signatures or not isinstance(signatures[0].get("hex"), str):
            raise ValueError(f"Collector {profile_id} returned no valid hex")

        sig = apply_cps_specs_to_sig(profile_id, signatures[0])
        merged = merge_collector_output_strict(
            profile_id,
            sig,
            allow_architect=allow_architect_fallback,
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
            "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
            "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
            "allow_architect_fallback": allow_architect_fallback,
            "strict": strict,
            "dry_run": dry_run,
            "skipped_profiles": skipped,
        },
        "profiles": profiles,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run signature collectors (lab: strict merge, provenance in JSON)."
    )
    parser.add_argument("--out", required=True, help="Output JSON path.")
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Protocol config directory (default: package config/).",
    )
    parser.add_argument("--policy", type=Path, default=None, help="capture_policy.yaml path.")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--allow-architect-fallback",
        action="store_true",
        help="Fill missing I2-I5 from ARCHITECT_DEFAULTS (off by default).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any profile has incomplete_slots.",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.out).resolve()
    config_dir = (args.config_dir or Path(__file__).resolve().parent / "config").resolve()
    policy_path = args.policy.resolve() if args.policy else None

    if args.dry_run:
        logger.warning("dry-run: fixtures/templates only")

    try:
        data = run_all(
            config_dir,
            out_path,
            timeout=args.timeout,
            dry_run=args.dry_run,
            allow_architect_fallback=args.allow_architect_fallback,
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
