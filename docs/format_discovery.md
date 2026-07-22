# format_discovery.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 1: Format Discovery**
Sample / synthetic / non-sensitive data only. No private operational data used.

## Confirmed format

The data is **nfdump binary flow files**, collector output written by the
nfdump capture daemon (`nfcapd`), storing NetFlow/IPFIX-style flow records in
nfdump's own compact binary format. Files are named `nfcapd.YYYYMMDDHHMM`
(one file per collection interval, ~5 minutes).

These are not raw packet captures and contain only the flow metadata.

## How the format was confirmed

1. **`file`** on a sample shows generic binary data, not text:
   ```
   file raw/2026-01/2026-01-01/nfcapd.202601010000
   # -> ... data
   ```
   It is not readable with `cat`/`less` and thus a binary collector file.

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

The `folders` file details the workflow. Each line is a month directory under
`raw/` to process. The anonymized output mirrors this structure under `anon/`.

## Readable fields

Exported with `nfdump -r <file> -o extended` (or `-o csv`). Each flow record
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

An illustrative record set (documentation only, real input is the binary
`nfcapd.*` files) is in `sample_flow_records.csv`.

## Sensitive vs preserved fields

| Class | Fields | Action |
|---|---|---|
| **Sensitive (identifying)** | src_ip, dst_ip, next_hop_ip, router/exporter IP | **anonymize** with nfanon |
| **Preserved (needed for analysis)** | time, protocol, src_port, dst_port, packets, bytes, TCP flags | **keep unchanged** |

## Tool research and recommendation

| Tool | Read / inspect | Collect | Convert | Anonymize | Validate | Decision |
|---|---|---|---|---|---|---|
| **nfdump** | Yes: binary, text, CSV, JSON, statistics | No | Can rewrite filtered nfdump files | No | Yes: records, totals, distributions, aggregations | **Use** as the reader and validation engine |
| **nfcapd** | No | Yes: NetFlow v5/v9 and IPFIX exporters | Collector output is already nfdump format | No | Supplies controlled synthetic input | **Use when synthetic exporter traffic must be collected** |
| **nfanon** | Reads nfdump input for rewriting | No | nfdump → anonymized nfdump | Yes: CryptoPAn IP pseudonymization | No analytical checks | **Use** as the anonymizer |
| **nfpcapd** | Reads packet captures or an interface | Yes | Packet metadata → nfdump flows | No | Can create approved test input | **Use** for the documented `sample.pcap` test path; packet payloads are not retained in nfdump output |
| **sfcapd** | No | Yes: sFlow | sFlow samples → nfdump format | No | Output can be checked with nfdump | Use only if discovery identifies sFlow input |
| **ft2nfdump / flow-tools** | Reads legacy flow-tools data | No | flow-tools → nfdump | No | Converted output can be checked with nfdump | Not required: discovery confirmed nfdump, not legacy flow-tools |
| **nfgen** | No | Generates nfdump test records | No | No | Useful for deterministic test fixtures | Optional development helper only; not required by this prototype |

### Test evidence

The completed Docker test used Debian Bookworm with Debian `nfdump`/`nfanon`
1.7.1. The included `sample.pcap` was converted with `nfpcapd` into one
`nfcapd.*` file containing 20 readable flow records. `nfdump` inspected the
converted file, `nfanon` produced a separate anonymized nfdump file, and the
validator confirmed preserved utility plus changed IP mappings.

`nfgen` is not required for the current workflow. It remains an optional
upstream development helper in `make_sample_data.sh` for environments that
already have it, but the documented and tested path is PCAP conversion.

**Recommendation:** keep the prototype to Bash + nfdump + nfanon, using
`nfpcapd` for approved PCAP-to-flow sample conversion and `nfcapd` only for the
built-in synthetic fallback.

## Supplementary: the nfdump suite

The tools used here are part of **nfdump** (Peter Haag), a BSD-licensed,
actively maintained suite for collecting and processing NetFlow (v5/v9 for the scope of this project),
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
