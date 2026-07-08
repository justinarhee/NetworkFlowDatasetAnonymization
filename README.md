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
├── Dockerfile                    # reproducible Debian image; builds nfgen
├── .dockerignore                 # excludes local data/secrets from build context
├── workflow.txt                  # complete Debian Docker commands
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

**Prerequisites (macOS):** Docker and Colima. The project image is based on
Debian Bookworm and builds the official nfdump v1.7.3 `nfgen` utility in a
separate builder stage. The runtime image contains `nfdump`, `nfanon`,
`nfcapd`, and `nfgen`.

```bash
colima start
docker build --platform linux/arm64 -t flow-anonymizer:debian .
docker run --rm -it --platform linux/arm64 \
  -v "$PWD":/work -w /work flow-anonymizer:debian
```

**Inside the Debian container:**

```bash
cat /etc/os-release
nfdump -V
command -v nfanon
command -v nfgen

# 1) create a local anonymization key (should never be committed)
./generate_key.sh                       #  or: export NFANON_KEY=<32-char-or-64-hex>

# 2) create sample nfdump binary files under raw/ (synthetic, non-sensitive data)
./make_sample_data.sh                   # nfgen, or automatic Bash+nfcapd fallback

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

> **Note:** `nfdump`/`nfanon` are separately licensed. `nfgen` is compiled
> from the official nfdump source during `docker build`; it is not downloaded
> as an unverified third-party binary. See `workflow.txt` for the full command
> sequence.

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
 validate:  export normalized records from raw and anon with nfdump
            compare preserved fields, distributions, time series, and top talkers
            derive every original IP and verify changed, deterministic mappings
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

## Validation results (Debian nfgen sample)

| Metric | Before | After |
|---|---|---|
| Flow records | 20 | 20 |
| Total packets | 466 | 466 |
| Total bytes | 117,760 | 117,760 |
| Preserved record fields | Baseline | Identical |
| Distributions and time series | Baseline | Identical |
| Source/destination top-talker structure | Baseline | Identical |
| Original IPs visible | Yes | **No** |

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


## Issues (Changes to be made/ Notes)
1) Produce real synthetic nfdump input
The repository currently contains only an illustrative CSV. raw/ has no binary nfcapd.* files, and [make_sample_data.sh (line 17)] cannot run here because nfgen is unavailable.
Run the prototype on Ubuntu with nfgen, or generate approved sample flows using nfcapd/nfpcapd. 

2) fixing poitn #1. nfgen isnt in macos nfdump suite. have to use docker 

3) Fix false-positive validation
Currently, [validate_flows.sh (line 41)]reports OVERALL: PASS even when raw/2026-01 does not exist and zero files were tested. It must fail when:
A listed input directory is missing.
No flow files are found.
An output file is missing.
Any validation command fails.

4) Implement every required validation check
The validator still needs to compare before versus after for:
Packet and byte distributions, not only totals.
Source and destination port distributions.
Time-series traffic volume.
Top-talker structure—the broader assignment explicitly requires this.
Ideally, every preserved record field: timestamps, protocol, ports, packets, bytes, and TCP flags.
At present, it only displays the anonymized destination-port distribution rather than comparing both sides [lines 60–63 (line 60)]

5) Make IP-removal checking data-driven
The current check only searches for three hard-coded IPv4 test prefixes ([lines 21–23 (line 21)](/sh:21)). Instead, extract all original source, destination, next-hop, and exporter addresses and confirm they are absent or transformed. Include IPv6 if the sample format supports it.

6) Replace illustrative results with genuine results
[validation_report.md (line 38)](/docs/validation_report.md:38) claims a five-record passing run, but the CSV is not converted into the nfdump files used by the scripts, and no corresponding output exists. Replace those figures and example mappings with results captured from an actual run.

7) Complete the tool-research deliverable
Expand the partial tools section in [format_discovery.md (line 83)](/docs/format_discovery.md:83) into the requested comparison table covering:
Reading
Collection
Conversion
Anonymization
Validation
Recommendation/use decision

Finish the privacy-and-utility evidence
The risk discussion is good, but the final report should explicitly demonstrate which analyses still work—especially distributions, time series, and top talkers—and show consistent/prefix-preserving mappings while explaining their privacy risk.

## Fixes to above 7 issues
Implemented issues 3–7.
Key changes:
1) [anonymize_flows.sh (line 96)]anonymize_flows.sh:96 now fails when folders are missing or contain zero flow files.

2) [validate_flows.sh (line 153)]validate_flows.sh:153 now validates preserved fields, distributions, time series, top talkers, IPv4/IPv6 removal, and deterministic mappings.

3) Fixed nfanon key formatting and removed the OpenSSL dependency in [generate_key.sh (line 12)]generate_key.sh:12.

4) Added the full tool comparison in [format_discovery.md (line 83)]docs/format_discovery.md:83.

5) Replaced illustrative validation claims with genuine Docker results in [validation_report.md (line 27)]docs/validation_report.md:27.

6) Expanded privacy/utility evidence in [privacy_risk_summary.md (line 44)]docs/privacy_risk_summary.md:44.

7) Updated README and workflow documentation.
Verification:
Zero-input run now exits 1 and reports FAIL.
Unchanged IP addresses are rejected.
Docker end-to-end test passed with 5 flows, 59 packets, and 42,128 bytes.
Local validation also passed.
Bash syntax and Git whitespace checks passed.


## nfgen update 

- Built official nfdump v1.7.3 nfgen.c for Linux ARM64.
- Installed at /usr/local/bin/nfgen in the running container.
- Persistent copy saved at .local-tools/nfgen and git-ignored.
- Updated [make_sample_data.sh (line 24)](/make_sample_data.sh:24) because nfgen always writes test.flows.nf and does not support -w.-

-  saved nfgen in the repo at .local-tools/nfgen, copy it into the container path:
cp .local-tools/nfgen /usr/local/bin/nfgen
