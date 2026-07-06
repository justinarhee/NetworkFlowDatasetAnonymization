# Flow Dataset Anonymization Prototype

> A reproducible pipeline for anonymizing **network flow metadata** (NetFlow / IPFIX / sFlow stored in nfdump format) so it can be shared for research and training **without exposing host identities** while preserving the fields that traffic analysis depends on.

![Shell](https://img.shields.io/badge/Bash-prototype-4EAA25?logo=gnu-bash&logoColor=white)
![Tooling](https://img.shields.io/badge/tooling-nfdump%20%7C%20nfanon-blue)
![Scope](https://img.shields.io/badge/data-synthetic%20only-lightgrey)

---

## Context & motivation

This prototype was built for the **CIARA / FIU** group. FIU's
[Center for Internet Augmented Research and Assessment (CIARA)](https://ciara.fiu.edu)
operates **[AmLight (Americas Lightpaths)](https://www.amlight.net)**, a
production, **software-defined (SDN)** research-and-education network that has
run on OpenFlow since 2014 and is now deeply programmable (P4 / In-band Network
Telemetry), interconnecting the U.S., Latin America, the Caribbean, and South
Africa.

Networks like AmLight are **composed of sFlow and NetFlow-style
telemetry** for real-time monitoring, traffic engineering, and security detection tools. 
This telemetry is operationally sensitive as it includes information regarding endpoints, topology, and communication patterns.
Before the flow data can be shared with students or researchers, the
identifying fields must be removed or anonymized while still being useful analysis.

> All data in this repository is **synthetic**
> (RFC 5737 / RFC 1918 ranges). No private operational data is included, in
> keeping with the project's data-handling restriction.

---

## What it does

- **Identifies** the data format by inspection.
- **Anonymizes** every IP field (source, destination, next-hop, router/exporter)
  with **nfanon**, which uses **CryptoPAn** prefix-preserving pseudonymization.
- **Preserves** other fields necessary for flow analysis (time, protocol, ports, packet and byte counts, TCP flags).
- **Preserves the folder structure**, writing anonymized output to a separate
  `anon/` tree and never modifying the original dataset.
- **Runs dry-run first**, logs every input→output, and **never exposes the key**.
- **Validates** that only the IP addresses have changed (other fields should be
  identical before/after) and that original IP addresses are unrevealed.

## Threat model

| Protected | Not protected by IP anonymization alone |
|---|---|
| Direct host/network identification via IP addresses | Behavioral fingerprints (ports, byte/packet volumes, timing) |
| Re-identification through a shared dataset | Injection & frequency-analysis attacks on prefix structure |
| Accidental exposure of raw operational addressing | Reversal by anyone holding the anonymization key |

CryptoPAn is **pseudonymization** cryptographic scheme that is keyed and reversible by design such that the subnet
structure survives for analysis. The residual controls are strict key
management, key rotation, and limiting who receives the data. See
[`docs/privacy_risk_summary.md`](docs/privacy_risk_summary.md) for the full
analysis and hardening options.

---

## Repository structure

```
.
├── README.md                     # this page
├── folders                       # month folders to process (e.g. 2026-01)
├── generate_key.sh               # create a local nfanon key (0600, git-ignored)
├── make_sample_data.sh           # populate raw/ with sample nfcapd.* files
├── anonymize_flows.sh            # MAIN workflow — dry-run by default, --run to execute
├── validate_flows.sh             # before/after validation
├── sample_flow_records.csv       # illustrative records (documentation only)
├── raw/   anon/   logs/          # data in / out / logs
└── docs/
    ├── format_discovery.md       # Deliverable 1 — confirmed format & fields
    ├── anonymization_workflow.md # Deliverable 2 — workflow
    ├── validation_report.md      # Deliverable 3 — before/after results
    ├── privacy_risk_summary.md   # Deliverable 4 — security, limitations, risks
    └── project_narrative.md      # how the project evolved
```

---

## Quick start — Testing

**Prerequisites (Ubuntu):** install the nfdump suite, which provides
`nfdump`, `nfanon`, `nfcapd`, `sfcapd`, and `nfgen`.

```bash
sudo apt-get update && sudo apt-get install -y nfdump
nfdump -V       # confirming installation and version
```

**Clone and run the full workflow:**

```bash
git clone https://github.com/justinarhee/NetworkFlowDatasetAnonymization.git
cd NetworkFlowDatasetAnonymization

# 1) create a local anonymization key (should never be committed)
./generate_key.sh                       #  or: export NFANON_KEY=<32-char-or-64-hex>

# 2) create sample nfdump binary files under raw/ (synthetic, non-sensitive data)
./make_sample_data.sh                   #  uses nfgen; falls back with instructions

# 3) inspect a file to confirm the format
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended | head

# 4) DRY-RUN: shows what would happen, writes nothing
./anonymize_flows.sh

# 5) RUN: anonymizes into anon/, mirroring raw/
./anonymize_flows.sh --run

# 6) VALIDATE: confirms only IPs changed and real IPs are gone
./validate_flows.sh
```

If you have `nfcapd.*` files to use as the dataset to be anonymized, add them into
`raw/<month>/<date>/` and add the `<month>` to the `folders` file. Steps 4–6 are unchanged.

> **Note:** `nfdump`/`nfanon` are not bundled here as they are separately
> licensed. If `make_sample_data.sh` can't find `nfgen`, it prints how to
> collect sample data with `nfcapd` or convert a pcap with `nfpcapd`.

---

## How it works

```
raw/ (nfdump binary)          anon/ (nfdump binary, IPs pseudonymized)
   │                                     ▲
   │  read `folders`                     │  mirror folder structure
   ▼                                     │
 for each nfcapd.* file  ──►  nfanon -K <key> -r <in> -w <out>  ──►  anon/<same path>
   │                              (CryptoPAn, prefix-preserving, IP fields only)
   ▼
 validate:  nfdump -r <in>  -I     vs     nfdump -r <out> -I     → counts must match
            nfdump -r <out> -o csv | grep <known real IP ranges> → must be empty
```

The prototype loops **file-by-file** with `nfanon -r/-w` specifically so the
directory tree is preserved.

### Field policy

| Anonymized (nfanon / CryptoPAn) | Preserved unchanged |
|---|---|
| Source IP, Destination IP | Time (start / end / duration) |
| Next-hop IP | Protocol |
| Router / exporter IP | Source & destination ports |
| | Packet count, Byte count |
| | TCP flags |

---

## Validation results (sample dataset)

| Metric | Before | After |
|---|---|---|
| Flow records | 5 | 5 |
| Total packets | 59 | 59 |
| Total bytes | 42,128 | 42,128 |
| Protocols | TCP=3, UDP=1, ICMP=1 | TCP=3, UDP=1, ICMP=1 |
| Dest ports | 443, 22, 53, 80, 0 | 443, 22, 53, 80, 0 |
| Real IPs visible | yes | **No** |

Prefix preservation is visible in the results: a source that appears in two
flows maps to the **same** pseudonym both times, and adjacent source addresses
map to adjacent pseudonyms. This allows pseudonymization of the IP addresses while
preserving the subnet structure such that subnet-level analysis is still valid. Full details
in [`docs/validation_report.md`](docs/validation_report.md).

---

## Security, limitations & next steps

Covered in depth in [`docs/privacy_risk_summary.md`](docs/privacy_risk_summary.md).
In short:

- **Reversible by design.** CryptoPAn is keyed pseudonymization, not
  irreversible anonymization. Protect and **rotate the key per release**.
- **Fingerprints remain.** Ports, volumes, and timing are preserved for
  analysis and can still fingerprint a host.
- **Prefix structure preservation allows injection and frequency-analysis attacks**.
- **Next steps and future explorations**:
  timestamp generalization, k-anonymity suppression of rare flow profiles,
  volume bucketing, and differential-privacy noise on **published aggregates
  only**. These trade utility for privacy and were deliberately left out of the
  in-scope prototype.

---

## Tooling & references

- **nfdump** (Peter Haag): BSD-licensed suite for collecting/processing
  NetFlow (v5/v9 for the scopes of this project), IPFIX, and sFlow. Provides `nfcapd` (NetFlow
  collector), `sfcapd` (sFlow collector), `nfdump` (reader/analyzer), and
  **`nfanon`** (CryptoPAn IP anonymizer). Current series 1.7.x.
  → https://github.com/phaag/nfdump
- **CryptoPAn**: prefix-preserving IP anonymization (Xu, Fan, Ammar, Moon).
- **AmLight / CIARA / FIU**: production SDN R&E network context and motivation.
  → https://www.amlight.net · https://ciara.fiu.edu
- **RFCs**: NetFlow v9 (RFC 3954), IPFIX (RFC 7011), documentation address
  ranges (RFC 5737), private ranges (RFC 1918).

---

## Repository regulations

**Committed:** scripts, documentation, `.gitignore`, the synthetic
`sample_flow_records.csv`, and the empty `raw/ anon/ logs/` skeleton
(`.gitkeep`).

**Never committed**: the anonymization **key**
(`secret/`, `*.key`), **raw flow data**, **anonymized output**, **logs**, and
anything containing real IPs, internal paths, or sensitive screenshots. See
[`docs/privacy_risk_summary.md`](docs/privacy_risk_summary.md).

---

## Author & acknowledgments

Built as a CIARA/FIU flow-data anonymization research activity. nfdump/nfanon by
Peter Haag (BSD). AmLight is operated by CIARA at FIU with NSF support.

## License

The nfdump suite is **not** included here and
is distributed separately under its own BSD license.
