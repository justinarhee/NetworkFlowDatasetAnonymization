#!/usr/bin/env bash
# make_sample_data.sh — populate raw/ with sample nfdump binary (nfcapd) files.
#
# nfcapd.* files are nfdump's binary format and cannot be hand-written. This
# helper builds them from a pcap using nfpcapd (part of the nfdump suite). The
# repo ships a synthetic, non-sensitive capture (sample.pcap); set PCAP to use
# your own instead.
set -euo pipefail
RAW_DIR="${RAW_DIR:-raw}"
PCAP="${PCAP:-sample.pcap}"
DEST="${DEST:-$RAW_DIR/2026-01/2026-01-01}"

command -v nfpcapd >/dev/null 2>&1 || {
  echo "ERROR: nfpcapd not found. Install the nfdump suite: sudo apt-get install nfdump" >&2
  exit 1
}

if [[ ! -f "$PCAP" ]]; then
  cat >&2 <<MSG
No pcap found at '$PCAP'. Options:
  * place a capture there (the repo ships sample.pcap), or
  * capture ~20s of your own traffic:
        sudo tcpdump -i any -w sample.pcap -G 20 -W 1
  * then re-run:  PCAP=sample.pcap ./make_sample_data.sh
MSG
  exit 1
fi

mkdir -p "$DEST"
echo "Converting $PCAP -> nfcapd files under $DEST ..."
nfpcapd -r "$PCAP" -w "$DEST"

shopt -s nullglob
files=("$DEST"/nfcapd.*)
if (( ${#files[@]} == 0 )); then
  echo "WARNING: no nfcapd.* files were produced — check the nfpcapd output above." >&2
  exit 1
fi
echo "Created ${#files[@]} file(s):"
printf '  %s\n' "${files[@]}"
echo "Inspect with:  nfdump -R $DEST -o extended | head"
