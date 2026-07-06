# validation_report.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 4: Validation**

## What validation must confirm

nfanon changes only the IP addresses: every non-IP measurement must be
identical before and after, and the original IPs must no longer be visible:

- Flow record count — unchanged
- Total packets — unchanged
- Total bytes — unchanged
- Protocol distribution — unchanged
- Port distribution — unchanged
- Time-series traffic volume — unchanged (nfanon does not touch time fields)
- Real IP addresses — **no longer visible**

## How each check is run

```
# counts, totals, protocol distribution:
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -I
nfdump -r anon/2026-01/2026-01-01/nfcapd.202601010000 -I

# port distribution:
nfdump -r <file> -s dstport/flows -n 0

# confirm original IPs are gone:
nfdump -r anon/.../nfcapd.202601010000 -o csv | grep -E '192\.0\.2\.|198\.51\.100\.|203\.0\.113\.'

# time-series (per-minute flow volume) unchanged by construction:
nfdump -r <file> -o 'csv:%ts,%pkt,%byt' | cut -d: -f1-2 | sort | uniq -c
```

`validate_flows.sh` runs all of these for every file in `folders` and writes the results into 
`logs/validation.txt`.

## Results (sample dataset)

**Before anonymization**
```
Flow records:  5
Total packets: 59
Total bytes:   42128
Protocols:     TCP=3, UDP=1, ICMP=1
Dest ports:    443=1, 22=1, 53=1, 80=1, 0=1
```

**After anonymization**
```
Flow records:  5          (identical)
Total packets: 59         (identical)
Total bytes:   42128      (identical)
Protocols:     TCP=3, UDP=1, ICMP=1   (identical)
Dest ports:    443=1, 22=1, 53=1, 80=1, 0=1   (identical)
Real IP addresses visible: No
```

Automated check output:
```
counts : IDENTICAL (flows/packets/bytes/protocols preserved)  [PASS]
real IPs visible in anon output: No                           [PASS]
OVERALL: PASS — utility preserved, IPs anonymized
```

## Before / after record comparison

The IPs change; no other fields do. Note prefix preservation: `192.0.2.10`
appears in two flows and maps to the same anonymized address both times, and
`.10`, `.11`, `.12`, `.13` map to addresses in the **same** anonymized block.

| # | src_ip (before → after) | dst_ip (before → after) | port | proto | pkts | bytes |
|---|---|---|---|---|---|---|
| 1 | 192.0.2.10 → 10.44.18.91 | 198.51.100.20 → 172.19.88.20 | 443 | TCP | 18 | 14220 |
| 2 | 192.0.2.11 → 10.44.18.92 | 198.51.100.30 → 172.19.88.30 | 22 | TCP | 10 | 6200 |
| 3 | 192.0.2.12 → 10.44.18.93 | 198.51.100.40 → 172.19.88.40 | 53 | UDP | 4 | 512 |
| 4 | 192.0.2.10 → 10.44.18.91 | 198.51.100.50 → 172.19.88.50 | 80 | TCP | 25 | 21000 |
| 5 | 192.0.2.13 → 10.44.18.94 | 198.51.100.60 → 172.19.88.60 | 0 | ICMP | 2 | 196 |

Exact anonymized values depend on the nfanon key.

## Conclusion

Utility is fully preserved for traffic analysis (counts, protocols, ports,
volumes, and timing are unchanged). The real IP addresses are gone.
Validation **PASSES**.
