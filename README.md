# Flow Dataset Anonymization Prototype

> A reproducible Bash pipeline that anonymizes **network flow metadata**
> (NetFlow / IPFIX stored in nfdump binary format) so it can be shared for
> research and training **without exposing host identities**, while preserving
> the fields that traffic analysis depends on.

![Shell](https://img.shields.io/badge/Bash-prototype-4EAA25?logo=gnu-bash&logoColor=white)
![Tooling](https://img.shields.io/badge/tooling-nfdump%20%7C%20nfanon-blue)
![Scope](https://img.shields.io/badge/data-synthetic%20only-lightgrey)

---

## Context & motivation

This prototype was built for the **CIARA / FIU** group. FIU's
[Center for Internet Augmented Research and Assessment (CIARA)](https://ciara.fiu.edu)
operates **[AmLight (Americas Lightpaths)](https://www.amlight.net)**, a
production, software-defined (SDN) research-and-education network interconnecting
the U.S., Latin America, the Caribbean, and South Africa.

Networks like AmLight rely on sFlow- and NetFlow-style telemetry for monitoring,
traffic engineering, and security detection. That telemetry is operationally
sensitive as it reveals endpoints, topology, and communication patterns. Before
flow data can be shared with students or researchers, the identifying fields must
be anonymized while preserving usability for data analysis.

> All data in this repository is **synthetic** (RFC 5737 documentation ranges and
> RFC 1918 private ranges). No private operational data is included, in keeping
> with the project's data-handling restriction.

---

## What it does

- **Confirms** the input format by inspection with `nfdump`.
- **Anonymizes** every IP field (source, destination, next-hop, router/exporter)
  using **`nfanon`**, which applies **CryptoPAn** prefix-preserving
  pseudonymization.
- **Preserves** every non-IP field needed for analysis (time, protocol, ports,
  packet and byte counts, TCP flags).
- **Mirrors the folder structure**, writing anonymized output to a separate
  `anon/` tree and never modifying the original `raw/` data.
- **Runs dry-run first** by default, logs every input→output, and **never exposes
  the key** (only a short fingerprint is logged).
- **Validates** that only the IP fields changed, that analytical structure is
  intact, and that no original IP addresses remain visible.

---

## Threat model

| Protected by IP anonymization | **Not** protected by IP anonymization alone |
|---|---|
| Direct host/network identification via IP addresses | Behavioral fingerprints (ports, byte/packet volumes, timing) |
| Re-identification from a shared dataset | Injection and frequency-analysis attacks on prefix structure |
| Accidental exposure of raw operational addressing | Reversal by anyone holding the anonymization key |

CryptoPAn is **keyed pseudonymization**, reversible by design so that subnet
structure survives for analysis. The residual controls are strict key management,
key rotation per release, and limiting who receives the data. See
[`docs/privacy_risk_summary.md`](docs/privacy_risk_summary.md) for the full
analysis.

---

## Repository structure

```
.
├── README.md                     # this page
├── folders                       # month folders to process with anonymize_flows.sh (one per line, e.g. 2026-01)
├── generate_key.sh               # create/rotate a local nfanon key (0600, git-ignored)
├── make_sample_data.sh           # populate raw/ with a synthetic nfcapd.* file
├── anonymize_flows.sh            # MAIN workflow — dry-run by default, --run to execute
├── validate_flows.sh             # before/after validation
├── sample.pcap                   # sample pcap file provided to test workflow
├── sample_flow_records.csv       # sample.pcap in csv format, for visualization purposes
├── raw/   anon/   logs/          # data in / out / logs (contents are git-ignored)
└── docs/
    ├── format_discovery.md       # Phase 1 — confirmed format, fields, tool research
    ├── anonymization_workflow.md # Phase 3 — prototype workflow
    ├── validation_report.md      # Phase 4 — before/after results
    └── privacy_risk_summary.md   # security, limitations, residual risk
```

---

## Prerequisites (Ubuntu)

Install the nfdump suite, which provides `nfdump`, `nfanon`, `nfcapd`, and
`nfpcapd`:

```bash
sudo apt-get update && sudo apt-get install -y nfdump
nfdump -V        # confirm installation and version (1.7.x)
```

Ubuntu does not package the optional `nfgen` test-record generator. If it is
absent, `make_sample_data.sh` automatically falls back to a built-in
Bash + `nfcapd` generator (see below). macOS does not ship `nfgen` at all; run
the full workflow inside a Linux container (see [`workflow.txt`](workflow.txt)).

---

## Quick start

```bash
git clone https://github.com/justinarhee/NetworkFlowDatasetAnonymization.git
cd NetworkFlowDatasetAnonymization

# 1) Create a local anonymization key
./generate_key.sh                       # writes secret/anon.key (perms 600)
#   or: export NFANON_KEY=<32-char-string | 0x + 64 hex digits>

# 2) Create sample data under raw/ (non-sensitive data generated)
./make_sample_data.sh                   # synthetic (nfgen, else Bash+nfcapd)
#   or convert your own captures:
#   ./make_sample_data.sh capture.pcap a.pcapng /path/to/pcap_dir

# 3) DRY-RUN: shows what would happen, writes nothing under anon/
./anonymize_flows.sh

# 4) RUN: anonymize into anon/, mirroring raw/
./anonymize_flows.sh --run

# 5) VALIDATE: confirm only IPs changed and originals are gone
./validate_flows.sh
cat logs/validation.txt
```

To anonymize your own data instead of the sample, drop `nfcapd.*` files into
`raw/<month>/<date>/` and either add `<month>` to the `folders` file (default
whole-dataset scope) or point the scripts at a specific path. Both
`anonymize_flows.sh` and `validate_flows.sh` accept a file, day, or month path
as a target, so you can process just one new day:

```bash
./anonymize_flows.sh --run raw/2026-02/2026-02-01     # anonymize only that day
./validate_flows.sh          raw/2026-02/2026-02-01     # validate only that day
```

With no target, the scripts use the `folders` file if present, otherwise the
whole `raw/` tree. `anonymize_flows.sh` skips inputs already anonymized under
`anon/` (use `--force` to overwrite).

> **Note:** `nfdump`/`nfanon` are separately licensed and are **not** bundled
> here. Without `nfgen`, `make_sample_data.sh` sends five synthetic NetFlow v5
> records to a short-lived local `nfcapd` collector over UDP and keeps exactly
> one verified, non-empty nfdump file.

---

## How it works

```
raw/ (nfdump binary)                anon/ (nfdump binary, IPs pseudonymized)
   │                                        ▲
   │  read `folders` (preflight)            │  mirror the folder structure
   ▼                                        │
 for each nfcapd.* file  ──►  nfanon -K <key> -r <in> -w <out>  ──►  anon/<same path>
   │                              (CryptoPAn, prefix-preserving, IP fields only)
   ▼
 validate (validate_flows.sh):
   nfdump -r <raw> -I     vs   nfdump -r <anon> -I         → counts/totals must match
   preserved fields, distributions, per-minute series      → must be identical
   extract every original IP from raw, check it in anon     → must be absent
```

`anonymize_flows.sh` loops **file-by-file** with `nfanon -r/-w` so each input
file produces one anonymized file in the mirrored location; the directory tree is
preserved instead of being collapsed into a single output.

---

## Validation results (synthetic sample)

The built-in generator writes five NetFlow v5 records:

| Metric | Before | After |
|---|---|---|
| Flow records | 5 | 5 |
| Total packets | 59 | 59 |
| Total bytes | 42,128 | 42,128 |
| Protocols | TCP=3, UDP=1, ICMP=1 | TCP=3, UDP=1, ICMP=1 |
| Destination ports | 443, 22, 53, 80, 0 | 443, 22, 53, 80, 0 |
| Real IPs visible | yes | **no** |

Prefix preservation is observable: a source that appears in two flows maps to the
**same** pseudonym both times, and adjacent source addresses map to adjacent
pseudonyms, so subnet-level analysis remains valid. Full details in
[`docs/validation_report.md`](docs/validation_report.md).

---

## Security, limitations & next steps

Covered in depth in [`docs/privacy_risk_summary.md`](docs/privacy_risk_summary.md).
In short:

- **Reversible by design.** CryptoPAn is keyed pseudonymization, not irreversible
  anonymization. Protect the key and **rotate it per release**.
- **Fingerprints remain.** Ports, volumes, and timing are preserved for analysis
  and can still fingerprint a host.
- **Prefix structure is preserved**, which enables injection and
  frequency-analysis attacks.
- **Possible future hardening** (deliberately out of scope here): timestamp
  generalization, k-anonymity suppression of rare flow profiles, volume
  bucketing, and differential-privacy noise on **published aggregates only**.
  Each trades utility for privacy.

---

## Tooling & references

- **nfdump** (Peter Haag): BSD-licensed suite for collecting and processing
  NetFlow (v5/v9), IPFIX, and sFlow. Provides `nfcapd` (NetFlow collector),
  `nfpcapd` (pcap→nfdump), `nfdump` (reader/analyzer), and **`nfanon`** (CryptoPAn
  IP anonymizer). Current series 1.7.x. → https://github.com/phaag/nfdump
- **CryptoPAn**: prefix-preserving IP anonymization (Xu, Fan, Ammar, Moon).
- **AmLight / CIARA / FIU**: production SDN R&E network context and motivation.
  → https://www.amlight.net · https://ciara.fiu.edu
- **RFCs**: NetFlow v9 (RFC 3954), IPFIX (RFC 7011), documentation address ranges
  (RFC 5737), private ranges (RFC 1918).

---

## Repository hygiene

**Committed:** scripts, documentation, `.gitignore`, the illustrative
`sample_flow_records.csv`, and the empty `raw/ anon/ logs/` skeleton
(`.gitkeep`).

**Never committed:** the anonymization **key** (`secret/`, `*.key`), **raw flow
data**, **anonymized output**, **logs**, and anything containing real IPs,
internal paths, or sensitive screenshots.

## License

The nfdump suite is not included here and is distributed separately under its own
BSD license. Built as a CIARA/FIU flow-data anonymization research activity;
AmLight is operated by CIARA at FIU with NSF support.
