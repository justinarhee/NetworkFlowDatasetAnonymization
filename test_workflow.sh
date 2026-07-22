#!/usr/bin/env bash
#
# test_workflow.sh — run the prototype end to end on the included sample.pcap.
#
# This script is meant to be run inside the Debian Docker container or another
# Linux environment with nfdump/nfanon/nfcapd/nfpcapd installed.
set -euo pipefail

RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
LOG_DIR="${LOG_DIR:-logs}"
SAMPLE_PCAP="${SAMPLE_PCAP:-sample.pcap}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found"
}

require_tool nfdump
require_tool nfanon
require_tool nfcapd
require_tool nfpcapd

[[ -f "$SAMPLE_PCAP" ]] || die "sample capture not found: $SAMPLE_PCAP"

chmod +x generate_key.sh make_sample_data.sh anonymize_flows.sh validate_flows.sh

echo "== Resetting generated local output =="
find "$RAW_DIR" "$ANON_DIR" "$LOG_DIR" -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
rm -rf secret

echo "== Creating local anonymization key =="
./generate_key.sh

echo "== Converting $SAMPLE_PCAP to nfdump format =="
./make_sample_data.sh "$SAMPLE_PCAP"

raw_file="$(find "$RAW_DIR" -type f -name 'nfcapd.*' | head -n 1)"
[[ -f "$raw_file" ]] || die "no nfcapd.* file was generated under $RAW_DIR"

records="$(
  nfdump -q -N -r "$raw_file" -o 'fmt:%cnt' |
    awk 'NF { count++ } END { print count + 0 }'
)"
[[ "${records:-0}" -gt 0 ]] || die "generated file has no readable records: $raw_file"
echo "Generated $raw_file ($records readable records)"

if [[ ! -f "$FOLDERS_FILE" ]] || ! grep -qx '2026-01' "$FOLDERS_FILE"; then
  echo "== Using temporary folders scope for this test =="
  test_folders="$(mktemp "${TMPDIR:-/tmp}/flow-folders.XXXXXX")"
  printf '%s\n' '2026-01' > "$test_folders"
  export FOLDERS_FILE="$test_folders"
fi

echo "== Dry-run anonymization =="
./anonymize_flows.sh

echo "== Run anonymization =="
./anonymize_flows.sh --run

echo "== Validate anonymized output =="
./validate_flows.sh

echo "== Validation report =="
cat logs/validation.txt
