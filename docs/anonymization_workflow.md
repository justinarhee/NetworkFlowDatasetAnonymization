# anonymization_workflow.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Phase 3: Prototype Workflow**

## What the prototype does

It anonymizes the **IP fields** in nfdump binary flow files using **nfanon**
(prefix-preserving CryptoPAn), mirrors the `raw/` folder structure into a
separate `anon/` folder, and validates that only the IP fields have changed.
Other fields such as time, protocol, ports, packets, bytes, and TCP flags retain
identical values so the data still supports traffic analysis.

## Which fields change vs stay

| Anonymized (nfanon) | Preserved (untouched) |
|---|---|
| Source IP | Time (start/end/duration) |
| Destination IP | Protocol |
| Next-hop IP | Source port, Destination port |
| Router/exporter IP | Packet count, Byte count |
| | TCP flags |

nfanon rewrites the IP addresses in the record (src, dst, next-hop, router)
using CryptoPAn, which is **prefix-preserving**. Addresses sharing a subnet
still share a subnet after anonymization, so subnet-level analysis remains intact.

## Files in the prototype

| File | Purpose |
|---|---|
| `folders` | lists the month folders under `raw/` to process (`2026-01`) |
| `generate_key.sh` | creates a local nfanon key (0600, git-ignored) |
| `make_sample_data.sh` | creates sample `nfcapd.*` files with nfgen or the built-in Bash+nfcapd fallback |
| `anonymize_flows.sh` | **main workflow**, dry-run by default, `--run` to execute |
| `validate_flows.sh` | before/after validation (Phase 4) |
| `logs/anonymize.log` | records every input→output and the key *fingerprint* |

## The required workflow, step by step

**1. Confirm the files are readable by nfdump.**
```
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended | head
```

**2. Inspect the fields.**
```
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -o extended
nfdump -r raw/2026-01/2026-01-01/nfcapd.202601010000 -I        # stats
```

**3. Create the key (never committed).**
```
./generate_key.sh          # writes secret/anon.key, perms 600
# or: export NFANON_KEY=<32-char-or-0x-plus-64-hex-string>
```

**4. Dry-run first (writes no anonymized output).**
```
./anonymize_flows.sh                 # default is dry-run
```
Prints which `nfanon` commands *would* run and which output files
*would* be created. It appends an audit log but does not create files under
`anon/`. Before either mode proceeds, preflight requires every listed folder
to exist and contain at least one matching flow file.

**5. Run it (preserves folder structure, writes to `anon/`).**
```
./anonymize_flows.sh --run
```
Internally, for each file it runs:
```
nfanon -K "$KEY" -r raw/<path>/nfcapd.* -w anon/<same path>/nfcapd.*
```
The `-r`/`-w` per-file loop is what preserves the tree by creating an anonymized file per
input file in the mirrored location. Using `nfanon -R dir -w onefile` would
collapse all the files into a single file and destroy the file-tree structure.

**6. Validate original vs anonymized.**
```
./validate_flows.sh        # see validation_report.md
```

The validator fails on missing/zero inputs or missing outputs. It compares all
required preserved fields, totals, distributions, time series, dataset-wide
top-talker structure, every discovered IPv4/IPv6 value, and deterministic
one-to-one pseudonym mappings.

**7. Document results** in Markdown (these deliverables).

## Dry-run example

```
mode        : DRY-RUN
key sha256  : 878a6185fc1e (fingerprint only — key never logged)
[dry-run] nfanon -K <hidden> -r raw/2026-01/2026-01-01/nfcapd.202601010000 -w anon/2026-01/2026-01-01/nfcapd.202601010000
[dry-run] nfanon -K <hidden> -r raw/2026-01/2026-01-01/nfcapd.202601010005 -w anon/2026-01/2026-01-01/nfcapd.202601010005
[dry-run] nfanon -K <hidden> -r raw/2026-01/2026-01-02/nfcapd.202601020000 -w anon/2026-01/2026-01-02/nfcapd.202601020000
DRY-RUN complete. 3 file(s) WOULD be anonymized. Re-run with --run.
```

## Key safety

- The key is read from `$NFANON_KEY` or `secret/anon.key`. It should never be
  printed, logged, committed, or written into any deliverable. Only a short
  `sha256` fingerprint appears in the log.
- `secret/`, `*.key`, `raw/`, `anon/`, and `logs/` data are in `.gitignore`.
- The key is a 32-character string or `0x` followed by 64 hex digits, as
  nfanon requires. The workflow also normalizes legacy unprefixed 64-hex keys
  in memory without printing them.
- Rotate the key per release to allow the fresh key to produce a completely different
  mapping, preventing cross-dataset correlation.
