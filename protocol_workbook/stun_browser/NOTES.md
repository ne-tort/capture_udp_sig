# STUN family — workbook notes

## RFC 5389 structure (first 20 bytes)
| Offset | Field |
|--------|-------|
| 0-1 | Message Type |
| 2-3 | Message Length |
| 4-7 | Magic Cookie `2112a442` |
| 8-19 | Transaction ID (12 bytes, random) |

## CPS hybrid (`cps_specs/stun.yaml`)
- Bytes 0-7 static in `<b 0x...>`
- Transaction ID → `<r 12>` (not fixed hex)

## Slot policy
- `stun` / `webrtc`: required `i1`, optional `i2`, max_slots=2
- `stun_browser`: required `i1`, `i2`
- I3–I5: **omit** in strict mode (not Architect)

## Fixes in lab
- `_resolve_stun_url()` reads `servers` from config
- `use_response: false` skips incoming STUN → i2
