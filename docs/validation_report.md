# validation_report.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 4: Validation**

## Validation policy

`validate_flows.sh` must prove that the required analytical data is unchanged and
that every IP field is pseudonymized. It **fails** (does not pass) when a listed
folder is missing, no `nfcapd.*` files are found, an anonymized counterpart is
missing, `nfdump` cannot read a file, or any comparison differs.

For every raw/anonymized file pair it compares:

- flow count and total packets/bytes,
- every preserved record field: start/end time, protocol, source/destination
  ports, packet count, byte count, and TCP flags,
- packet, byte, protocol, source-port, and destination-port distributions,
- per-minute flow, packet, and byte time series.

Across the complete dataset it also compares source and destination top-talker
structure and validates all source, destination, next-hop, and router/exporter IP
fields. Original addresses are derived from the raw data rather than from
hard-coded prefixes, so the check covers both IPv4 and IPv6. The mapping check
confirms that each original address maps to one changed pseudonym and that no two
originals collide in the tested data.

## Docker test result (sample.pcap conversion)

Tested July 22, 2026 in the Debian Bookworm Docker image with Debian
`nfdump`/`nfanon` 1.7.1. The included `sample.pcap` was converted to nfdump
format with `nfpcapd`, producing one `nfcapd.*` file with 20 readable flow
records. Raw, anonymized, key, and log artifacts remain git-ignored.

| Check | Before | After | Result |
|---|---:|---:|---|
| Flow records | 20 | 20 | PASS |
| Total packets | 141 | 141 | PASS |
| Total bytes | 29,969 | 29,969 | PASS |
| Preserved record fields | Baseline | Identical | PASS |
| Packet/byte distributions | Baseline | Identical | PASS |
| Protocol and port distributions | Baseline | Identical | PASS |
| Per-minute time series | Baseline | Identical | PASS |
| Source/destination top-talker structure | Baseline | Identical | PASS |
| Original IPs visible | Yes | No | PASS |
| Deterministic, collision-free mapping | N/A | Confirmed | PASS |

Automated output:

```text
input files discovered: 1
BEFORE: flows=20, packets=141, bytes=29969
AFTER : flows=20, packets=141, bytes=29969
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
files checked: 1/1
OVERALL: PASS — required utility preserved and all IP fields pseudonymized
```

Exact pseudonyms are intentionally omitted: they depend on the secret key and are
unnecessary for demonstrating the checks.

## Reproduce the validation

```bash
./test_workflow.sh
```

Or manually:

```bash
./generate_key.sh
./make_sample_data.sh sample.pcap
./anonymize_flows.sh          # preflight + dry-run
./anonymize_flows.sh --run
./validate_flows.sh
cat logs/validation.txt
```

The generated `logs/validation.txt` is the authoritative report for the current
local dataset. It is deliberately git-ignored because it can contain internal
paths.
