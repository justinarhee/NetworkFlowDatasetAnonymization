# anonymization_workflow.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 3: Prototype Workflow**

## What the prototype does

It anonymizes the **IP fields** in nfdump binary flow files using **`nfanon`**
(prefix-preserving CryptoPAn), mirrors the `raw/` folder structure into a
separate `anon/` folder, and validates that only the IP fields changed. All
non-IP fields (time, protocol, ports, packets, bytes, TCP flags) keep identical
values, so the data still supports traffic analysis.

## Which fields change vs stay

| Anonymized (nfanon) | Preserved (untouched) |
|---|---|
| Source IP | Time (start/end/duration) |
| Destination IP | Protocol |
| Next-hop IP | Source port, Destination port |
| Router/exporter IP | Packet count, Byte count |
| | TCP flags |

`nfanon` rewrites the IP addresses in each record (src, dst, next-hop, router)
using CryptoPAn, which is **prefix-preserving**: addresses sharing a subnet still
share a subnet after anonymization, so subnet-level analysis remains intact.

## Files in the prototype

| File | Purpose |
|---|---|
| `folders` | optional allowlist of folders under `raw/` to process (e.g. `2026-01`) |
| `generate_key.sh` | creates/rotates a local nfanon key (0600, git-ignored) |
| `make_sample_data.sh` | creates sample data: converts one or more pcaps, or writes a synthetic `nfcapd.*` file via nfgen or the Bash+nfcapd fallback |
| `anonymize_flows.sh` | **main workflow** — dry-run by default, `--run` to execute |
| `validate_flows.sh` | before/after validation (Phase 4) |
| `logs/anonymize.log` | records every input→output and the key *fingerprint* only |

## Choosing what to process (targets vs the `folders` file)

`anonymize_flows.sh` and `validate_flows.sh` decide which files to act on using
the same three-tier rule, checked in order:

1. **Command-line path target(s).** Pass a file, a day directory, or a month
   directory and only that is processed — e.g. `./anonymize_flows.sh --run
   raw/2026-01/2026-01-02`. This is how you anonymize or validate just one new
   day without touching the rest of the dataset.
2. **The `folders` file**, if present and non-empty. Each non-blank, non-`#`
   line names a folder under `raw/` to process recursively. This is the default
   whole-dataset scope; think of it as an allowlist that documents the intended
   inputs and drives the preflight.
3. **The entire `raw/` tree**, if no target is given and no `folders` file
   exists. To process everything, either list all months in `folders` or remove
   the file.

`anonymize_flows.sh` additionally **skips any input whose `anon/` counterpart
already exists**, so a full re-run does not redo finished work; pass `--force`
to overwrite.

## Workflow, step by step

**1. Confirm the files are readable by nfdump.**
```
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended | head
```

**2. Inspect the fields and statistics.**
```
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -I        # stats
```

**3. Create the key (never committed).**
```
./generate_key.sh          # writes secret/anon.key, perms 600
# or: export NFANON_KEY=<32-char-string | 0x + 64 hex digits>
```
`generate_key.sh` draws 32 random bytes from `/dev/urandom`, writes them as
`0x` + 64 hex digits, sets permissions to `600`, and prints only a short sha256
fingerprint. Re-run with `--force` to rotate (replace) an existing key.

**4. Dry-run first (writes no anonymized output).**
```
./anonymize_flows.sh                          # default scope (folders/raw), dry-run
./anonymize_flows.sh raw/2026-01/2026-01-02   # dry-run just one day
```
Before either mode proceeds, a preflight requires that every resolved
folder/target exists and contains at least one `nfcapd.*` file; otherwise the
script prints `PRE-FLIGHT FAILED` and exits non-zero. The dry-run then prints the
`nfanon` command that *would* run for each discovered file and appends an audit
log, but creates nothing under `anon/`.

**5. Run it (mirrors folder structure into `anon/`).**
```
./anonymize_flows.sh --run                    # default scope
./anonymize_flows.sh --run raw/2026-01/2026-01-02   # only that day
./anonymize_flows.sh --run --force            # overwrite existing anon/ outputs
```
Internally, for each input file it runs:
```
nfanon -K "$KEY" -r raw/<path>/nfcapd.* -w anon/<same path>/nfcapd.*
```
The per-file `-r`/`-w` loop is what preserves the tree — one anonymized file per
input file in the mirrored location. Using `nfanon -R <dir> -w <onefile>` would
instead collapse every file into one output and destroy the folder structure.
Files already present under `anon/` are skipped unless `--force` is given.

**6. Validate original vs anonymized.**
```
./validate_flows.sh                           # validate the default scope
./validate_flows.sh raw/2026-01/2026-01-02    # validate only that day
cat logs/validation.txt
```
The validator uses the same target/`folders`/`raw` resolution and fails on
missing/zero inputs or missing outputs. It compares the preserved fields,
totals, distributions, per-minute time series, dataset-wide top-talker
structure, every discovered IPv4/IPv6 address, and the deterministic one-to-one
pseudonym mapping.

**7. Document results** in Markdown (these deliverables).

## Dry-run example (synthetic sample: one file)

```
mode        : DRY-RUN
key sha256  : 878a6185fc1e (fingerprint only — key never logged)
[dry-run] nfanon -K <hidden> -r raw/2026-01/2026-01-01/nfcapd.202601010000 -w anon/2026-01/2026-01-01/nfcapd.202601010000
DRY-RUN complete. 1 file(s) WOULD be anonymized. Re-run with --run.
```

With more folders/files listed in `folders`, one `[dry-run]` line appears per
discovered file and the final count grows accordingly.

## Key safety

- The key is read from `$NFANON_KEY` or `secret/anon.key`. It is never printed,
  logged, committed, or written into any deliverable — only a short sha256
  fingerprint appears in the log.
- `secret/`, `*.key`, `raw/`, `anon/`, and `logs/` data are in `.gitignore`.
- `nfanon` accepts a literal 32-character key or `0x` + 64 hex digits.
  `anonymize_flows.sh` also normalizes a legacy unprefixed 64-hex key in memory
  (adding the `0x`) without printing it.
- **Rotate the key per release.** A fresh key yields an entirely different
  mapping, preventing cross-dataset correlation.
