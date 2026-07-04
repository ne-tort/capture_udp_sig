# CHECKLIST: dtls

## A — Semantics
- [ ] Spec: RFC 6347
- [ ] Typical UDP packets: DTLS records (ClientHello, handshake)
- [ ] Fixed vs variable fields documented
- [ ] Target chain length: max 5 slots
- [ ] Empty optional slots policy: omit line (never `I2=` empty)

## B — Capture
- [ ] Collector: `sip_dtls_collector.DtlsSignatureCollector`
- [ ] BPF filter documented in workbook notes
- [ ] Live run (WSL): `poetry run python audit_capture.py --profile dtls --strict`
- [ ] Pcap saved under `captures/`
- [ ] `poetry run python analyze_pcap.py --pcap captures/run1.pcap`

## C — CPS mapping
- [ ] Per-slot: full `<b 0x>` or hybrid (`cps_specs/dtls.yaml`)
- [ ] Variable fields use `<r>`, `<t>`, `<rc>` where required
- [ ] CPS validator: 0 errors

## D — Verification
- [ ] `slot_sources` has no `architect` in strict mode
- [ ] `compare_architect.py --profile dtls` reviewed
- [ ] 3 stable captures (live) or fixture documented (dry-run)

## E — Slot policy
- [ ] Required slots: i1, i2
- [ ] Documented in `capture_policy.yaml`
- [ ] `export_for_panel()` omits empty slots

## Status
- [ ] Definition of Done (plan phase 6)
