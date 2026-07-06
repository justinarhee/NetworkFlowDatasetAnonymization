# format_discovery.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 1: Format Discovery**
Sample / synthetic / non-sensitive data only. No private operational data used.

## Confirmed format

The data is **nfdump binary flow files** — collector output written by the
nfdump capture daemon (`nfcapd`), storing NetFlow/IPFIX-style flow records in
nfdump's own compact binary format. Files are named `nfcapd.YYYYMMDDHHMM`
(one file per collection interval, typically 5 minutes).

These are **not** raw packet captures and contain **no payloads** — only flow
metadata (who talked to whom, how much, when).

## How the format was confirmed (by inspection, not assumption)

1. **`file`** on a sample shows generic binary data, not text:
   ```
   file raw/2026-01/2026-01-01/nfcapd.202601010000
   # -> ... data
   ```
   It is not readable with `cat`/`less` (it is a binary collector file).

2. **`nfdump` reads it**, which is the definitive confirmation that it is a
   valid nfdump binary file:
   ```
   nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended
   ```

3. **`nfdump -I`** prints the file's internal statistics header (identifier,
   flow/packet/byte totals, per-protocol counts), confirming record structure:
   ```
   nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -I
   ```

## Folder structure

```
raw/
  2026-01/
    2026-01-01/
      nfcapd.202601010000
      nfcapd.202601010005
    2026-01-02/
      nfcapd.202601020000
anon/                     # mirror of raw/, created by the prototype
  2026-01/ ...
folders                   # lists the top-level month folders to process:
                          #   2026-01
```

The `folders` file drives the workflow; each line is a month directory under
`raw/` to process. The anonymized output mirrors this structure under `anon/`.

## Readable fields

Exported with `nfdump -r <file> -o extended` (or `-o csv`), each flow record
contains:

| Field | Meaning |
|---|---|
| start_time / end_time / duration | flow timing (`%ts %te %td`) |
| src_ip / dst_ip | source / destination IP (`%sa %da`) |
| src_port / dst_port | source / destination port (`%sp %dp`) |
| protocol | TCP / UDP / ICMP (`%pr`) |
| packets / bytes | flow volume (`%pkt %byt`) |
| tcp_flags | cumulative TCP flags (`%flg`) |
| next_hop_ip | next-hop router IP (`%nh`) |
| router_ip / exporter | exporting router IP (`%ra`) |
| tos | type of service (`%tos`) |
| src_as / dst_as | BGP AS numbers, if present |

An illustrative record set (documentation only — the real input is the binary
`nfcapd.*` files) is in `sample_flow_records.csv`.

## Sensitive vs preserved fields

| Class | Fields | Action |
|---|---|---|
| **Sensitive (identifying)** | src_ip, dst_ip, next_hop_ip, router/exporter IP | **anonymize** with nfanon |
| **Preserved (needed for analysis)** | time, protocol, src_port, dst_port, packets, bytes, TCP flags | **keep unchanged** |

## Tools tested

| Tool | Result |
|---|---|
| **nfdump** | reads the binary files; exports fields as text/CSV; prints statistics (`-I`, `-s`) — **works** |
| **nfanon** | anonymizes all IP fields with prefix-preserving CryptoPAn — **works** |
| **nfcapd** | used only to collect/generate sample data (not needed to read existing files) |

**Conclusion:** the format is confirmed nfdump binary; nfdump reads it and
nfanon anonymizes it. The prototype workflow (Phase 3) is built on these two
tools plus Bash.

## Supplementary reference — the nfdump suite

The tools used here are part of **nfdump** (Peter Haag), a BSD-licensed,
actively maintained suite for collecting and processing NetFlow (v1/v5/v7/v9),
IPFIX, and sFlow data (current series 1.7.x). Repository:
<https://github.com/phaag/nfdump>. Relevant components:

| Tool | Role |
|---|---|
| `nfcapd` | NetFlow collector daemon → writes nfdump binary files |
| `sfcapd` | sFlow collector daemon → writes nfdump binary files |
| `nfpcapd` | converts live interface / pcap traffic to nfdump binary |
| `nfdump` | reads/filters/aggregates nfdump binary files; exports text/CSV/JSON |
| `nfanon` | anonymizes IP addresses using CryptoPAn (used by this prototype) |
| `ft2nfdump` | converts legacy flow-tools files to nfdump format |

The collector→store→process model (`Exporter → nfcapd/sfcapd → nfdump`) and the
5-minute `nfcapd.YYYYMMDDhhmm` file rotation are why the sample dataset is laid
out as dated folders of `nfcapd.*` files.

### Relevance to CIARA / AmLight

AmLight — the CIARA/FIU production SDN research network — is instrumented with
**sFlow** and NetFlow-style telemetry. `sfcapd`/`nfcapd` collect that telemetry
into nfdump binary files, and `nfanon` is the natural, in-toolchain way to
anonymize the IP fields before the data is shared for research or training.
