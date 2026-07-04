# QUIC / quic_browser — workbook notes

## RFC 9000 packet types in chain
- Initial (long header, first byte & 0x80)
- Handshake / 0-RTT coalesced in same UDP datagram when `split_coalesced=false`
- `build_quic_packet_chain` orders: initial candidates → long-header → raw outgoing

## Capture settings (`quic_browser_targets.json`)
- `split_coalesced`: false (default)
- `https_quic_tcp` + `tls_clienthello_as_i1`: I1=TLS ClientHello, I2–I5=QUIC

## Strict lab status (dry-run)
- Fixtures provide 5/5 slots without Architect
- Live: need WSL + tcpdump + Chromium; target `_capture_chain_len=5`

## Commands
```bash
poetry run python audit_capture.py --profile quic_browser --strict
poetry run python compare_architect.py --profile quic_browser --dry-run
```
