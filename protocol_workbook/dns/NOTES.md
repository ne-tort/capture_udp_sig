# DNS — workbook notes

## Live capture (`dns_collector.py`)
- Trigger: `dig @resolver domain A`
- BPF: `udp and port 53`
- I1 = first DNS query, I2–I5 = up to 4 responses

## Strict policy
- Required: `i1` only
- I2–I5 optional until live capture returns multiple responses

## RFC 1035 variable fields
- Transaction ID (2 bytes) — changes per query
- TTL in responses — candidate for `<r>` / omit in static `<b>`
