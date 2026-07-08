# Validation Report

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 4**

## Validation policy

`validate_flows.sh` must prove that the required analytical data is unchanged
and every IP field is pseudonymized. It fails—not passes—when a listed folder
is missing, no `nfcapd.*` files are found, an anonymized counterpart is
missing, nfdump cannot read a file, or any comparison differs.

For every raw/anonymized file pair it compares:

- flow count and total packets/bytes,
- every preserved record field: start/end time, protocol, source/destination
  ports, packet count, byte count, and TCP flags,
- packet, byte, protocol, source-port, and destination-port distributions,
- per-minute flow, packet, and byte time series.

Across the complete dataset it also compares source and destination top-talker
traffic structure and validates all source, destination, next-hop, BGP
next-hop, and router/exporter IP fields. Original addresses are derived from
the raw data rather than from hard-coded prefixes, so the check covers both
IPv4 and IPv6. The mapping check confirms that each original address maps to
one changed pseudonym and that no two originals collide in the tested data.

## Genuine Docker test result

Tested July 7, 2026 using Ubuntu, nfdump/nfanon 1.7.3, and five synthetic
NetFlow v5 records collected by nfcapd. Raw, anonymized, key, and log artifacts
remain git-ignored.

| Check | Before | After | Result |
|---|---:|---:|---|
| Flow records | 5 | 5 | PASS |
| Total packets | 59 | 59 | PASS |
| Total bytes | 42,128 | 42,128 | PASS |
| Protocols | TCP=3, UDP=1, ICMP=1 | Same | PASS |
| Preserved record fields | Baseline | Identical | PASS |
| Packet/byte distributions | Baseline | Identical | PASS |
| Source/destination port distributions | Baseline | Identical | PASS |
| Per-minute time series | Baseline | Identical | PASS |
| Source/destination top-talker structure | Baseline | Identical | PASS |
| Original IPs visible | Yes | No | PASS |
| Deterministic, collision-free mapping | N/A | Confirmed in tested data | PASS |

Automated output:

```text
input files discovered: 1
BEFORE: flows=5, packets=59, bytes=42128
AFTER : flows=5, packets=59, bytes=42128
record count and packet/byte totals: identical [PASS]
all preserved record fields (time/protocol/ports/packets/bytes/TCP flags): identical [PASS]
packet distribution: identical [PASS]
byte distribution: identical [PASS]
protocol distribution: identical [PASS]
source-port distribution: identical [PASS]
destination-port distribution: identical [PASS]
per-minute time-series flow/packet/byte volume: identical [PASS]
source top-talker structure: identical [PASS]
destination top-talker structure: identical [PASS]
all original IP addresses were replaced (data-driven IPv4/IPv6 check) [PASS]
IP pseudonyms are changed, deterministic, and collision-free across the dataset [PASS]
OVERALL: PASS — required utility preserved and all IP fields pseudonymized
```

Exact pseudonyms are intentionally omitted: they depend on the secret key and
are unnecessary for demonstrating the checks.

### nfgen compatibility run

The official nfdump `v1.7.3` nfgen test utility was also compiled for Linux
ARM64 and exercised through the same workflow. It generated 20 readable test
records containing IPv4 and IPv6 extensions. Before and after totals were 20
records, 466 packets, and 117,760 bytes; every validation check passed.

## Reproduce the validation

```bash
./anonymize_flows.sh          # preflight + dry run
./anonymize_flows.sh --run
./validate_flows.sh
cat logs/validation.txt
```

The generated `logs/validation.txt` is the authoritative report for the
current local dataset. It is deliberately ignored by Git because it can
contain internal paths.
