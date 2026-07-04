# CHECKLIST: webrtc

## A — Semantics
- [ ] Spec: RFC 5389 via WebRTC ICE
- [ ] Typical UDP packets: STUN Binding via ICE
- [ ] Fixed vs variable fields documented
- [ ] Target chain length: max 2 slots
- [ ] Empty optional slots policy: omit line (never `I2=` empty)

## B — Capture
- [ ] Collector: `browser_stun_collector.py`
- [ ] BPF filter documented in workbook notes
- [ ] Live run (WSL): `poetry run python audit_capture.py --profile webrtc --strict`
- [ ] Pcap saved under `captures/`
- [ ] `poetry run python analyze_pcap.py --pcap captures/run1.pcap`

## C — CPS mapping
- [ ] Per-slot: full `<b 0x>` or hybrid (`cps_specs/webrtc.yaml`)
- [ ] Variable fields use `<r>`, `<t>`, `<rc>` where required
- [ ] CPS validator: 0 errors

## D — Verification
- [ ] `slot_sources` has no `architect` in strict mode
- [ ] `compare_architect.py --profile webrtc` reviewed
- [ ] 3 stable captures (live) or fixture documented (dry-run)

## E — Slot policy
- [ ] Required slots: i1
- [ ] Documented in `capture_policy.yaml`
- [ ] `export_for_panel()` omits empty slots

## Status
- [ ] Definition of Done (plan phase 6)
