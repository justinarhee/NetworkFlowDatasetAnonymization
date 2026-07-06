# Project Narrative — Process, Decisions, and Evolution

This document records how the prototype was developed, what was tried, what
changed, and why. It is intended both as an engineering log and as an honest
account of the design trade-offs made along the way.

## Phase 0 — Understanding the problem

The goal was to prepare **network flow datasets** (NetFlow / IPFIX / sFlow
metadata, not packet payloads) so they can be shared for research and training
**without exposing host identities**, while keeping the data useful for
traffic analysis.

The motivating context is real: FIU/CIARA operates **AmLight**, a production
SDN research network that is heavily instrumented with **sFlow** and NetFlow-
style telemetry. Flow telemetry from such a network is sensitive — it reveals
endpoints, topology, and cross-border research collaborations — so the fields
that identify hosts must be removed before the data leaves the operational
environment.

Early work established the fundamentals: what a flow record contains, which
fields are sensitive (IP addresses, and secondarily ASNs, interfaces, timing),
which are needed for analysis (protocol, ports, packet/byte counts, timing,
TCP flags), and the safe-handling rules (synthetic data only; never expose the
anonymization key).

## Phase 1 — Broad exploration (research spike)

Before settling on a design, a deliberately broad prototype was built to
understand the whole problem space:

- **Format-agnostic ingestion.** A detector that identifies each in-scope
  format by inspecting magic bytes / version fields rather than assuming —
  NetFlow v5 (`0x0005`), v9 (`0x0009`), IPFIX (`0x000A`), sFlow (4-byte version
  `5`), nfdump (magic `0xA50C`), flow-tools (`0xCF`), and CSV — decoding each
  into one normalized table.
- **A layered anonymization stack** aimed at resisting *injection* and
  *fingerprinting* attacks that plain prefix-preserving anonymization is weak
  against: CryptoPAn on IPs, HMAC-SHA256 pseudonyms for ASNs/interfaces, keyed
  timestamp jitter, coarse bucketing of ports/volumes, **k-anonymity**
  suppression of rare flow profiles, and differential-privacy noise reserved
  for aggregate query outputs.

This spike was valuable: it produced a clear, well-referenced understanding of
the formats and of the privacy/utility trade-offs, and it directly informed the
threat model and the "future work" section of the risk analysis.

## Phase 2 — Aligning to the authoritative requirements

When the definitive assignment specification arrived, it **narrowed the scope
substantially**, and reading it carefully changed the design:

- **Tools were restricted** to Ubuntu, **nfdump**, **nfanon**, **Bash**, and
  **Markdown**. A large custom (Python) engine was therefore out of scope.
- **Anonymization was scoped to IP fields only**, using **nfanon**.
- **Everything else had to remain byte-identical.** The required validation
  explicitly checks that record count, total packets, total bytes, protocol
  distribution, and port distribution are **the same before and after**.

This surfaced an important realization: several of the "advanced" schemes from
Phase 1 would have **failed** the assignment's validation. k-anonymity
suppression removes rows (changing the record count); timestamp jitter changes
the time fields; volume/port bucketing changes bytes and ports. Techniques that
strengthen privacy in a different setting would here have broken the explicit
utility requirement.

**Decision:** deliver exactly what the specification requires — a Bash workflow
built on nfdump + nfanon that anonymizes IPs only and preserves everything else
— and reposition the Phase 1 exploration as documented **future work** for a
scenario where wider data sharing justifies trading utility for privacy.

## Phase 3 — The delivered prototype

The final prototype is intentionally small, auditable, and faithful to the
requirements:

- `anonymize_flows.sh` — reads the `folders` list, walks `raw/` for
  `nfcapd.*` files, and runs `nfanon -K <key> -r <in> -w <out>` **per file** so
  the folder structure is mirrored into `anon/`. Dry-run by default; `--run` to
  execute; every action logged; the key reduced to a fingerprint in logs.
- `validate_flows.sh` — compares `nfdump -r … -I` statistics before/after
  (counts, protocols, volumes must match) and greps the anonymized output to
  confirm the original IP ranges are gone.
- `generate_key.sh` / `make_sample_data.sh` — local key creation and synthetic
  sample generation, so the workflow is reproducible by anyone.
- Four Markdown deliverables documenting format discovery, the workflow,
  validation, and the privacy-risk analysis.

The Bash logic was verified end-to-end with tool stubs (dry-run, structure
mirroring, key handling, and validation parsing all behave correctly). Actual
anonymization runs on an Ubuntu host with nfdump/nfanon installed.

## What changed, at a glance

| Dimension | Phase 1 exploration | Phase 3 delivered |
|---|---|---|
| Formats | all seven, custom detector/decoders | nfdump binary (confirmed by inspection) |
| Engine | custom Python multi-scheme stack | nfdump + nfanon + Bash |
| Fields changed | IPs + ASNs + interfaces + time + volumes | **IP fields only** |
| Rare-flow handling | k-anonymity suppression | none (record count must be preserved) |
| Timing | keyed jitter + bucketing | preserved exactly |
| Role of the extra schemes | core of the design | documented future work |

## Lessons and engineering judgment

- **Requirements first.** The most important design decision was recognizing
  that a more sophisticated pipeline was the *wrong* answer here because it
  violated an explicit constraint. Matching the specification precisely is a
  feature, not a limitation.
- **Utility vs. privacy is a real dial, not a solved problem.** Every privacy
  gain (suppression, noise, generalization) costs analytical utility. The right
  operating point depends on who receives the data and what they must be able to
  analyze — which is why the prototype ships two clearly-labeled positions
  (strict IP-only now; stronger options documented for later).
- **Honesty about guarantees.** Prefix-preserving anonymization is reversible
  pseudonymization, not irreversible anonymization. Saying so plainly — and
  building the key-handling discipline around it — is part of doing this
  responsibly.
