#!/usr/bin/env bash
# make_sample_data.sh — populate raw/ with sample nfdump binary files.
#
# nfdump binary files (nfcapd.*) cannot be hand-written; they are produced by
# the nfdump toolchain. This helper uses nfgen (the nfdump test-data generator,
# shipped with the suite) to create synthetic, non-sensitive sample files that
# match the folder layout in ./folders. Run on a machine with nfdump installed.
#
# If nfgen is unavailable, collect sample data instead with nfcapd (see README).
set -euo pipefail
RAW_DIR="${RAW_DIR:-raw}"
declare -a TARGETS=(
  "2026-01/2026-01-01/nfcapd.202601010000"
  "2026-01/2026-01-01/nfcapd.202601010005"
  "2026-01/2026-01-02/nfcapd.202601020000"
)
if ! command -v nfgen >/dev/null 2>&1; then
  cat >&2 <<'MSG'
nfgen not found. Two options to create sample nfcapd files:
  1) Install nfdump (which usually ships nfgen):  sudo apt-get install nfdump
  2) Collect live/replayed data:
        nfcapd -l raw/2026-01/2026-01-01 -p 2055 &   # then send NetFlow to :2055
     or convert a pcap:
        nfpcapd -r sample.pcap -l raw/2026-01/2026-01-01
MSG
  exit 1
fi
for t in "${TARGETS[@]}"; do
  mkdir -p "$RAW_DIR/$(dirname "$t")"
  # nfgen writes a small set of synthetic test flows to the given file.
  nfgen -w "$RAW_DIR/$t"
  echo "generated $RAW_DIR/$t"
done
echo "Done. Inspect with:  nfdump -r $RAW_DIR/${TARGETS[0]} -o extended"
