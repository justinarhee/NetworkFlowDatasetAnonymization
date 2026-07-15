#!/usr/bin/env bash
#
# make_sample_data.sh — CIARA/FIU Flow Dataset Anonymization Prototype
# ============================================================================
# PURPOSE
#   Produce nfdump binary (nfcapd.*) flow files for the prototype to anonymize.
#   It creates either (a) real flow files converted from one or more packet
#   captures you supply, or (b) synthetic, non-sensitive sample flows when no
#   capture is given — so the pipeline can always be exercised end to end.
#
# INPUT (chooses a method automatically, in this order):
#   1. USER-PROVIDED PCAP(S) — one or more .pcap/.pcapng paths and/or directories
#      passed as arguments (or via PCAP="a.pcap b.pcap"). Each capture is
#      converted to flow records with nfpcapd. Directories are searched
#      (non-recursively at find default: recursively) for *.pcap/*.pcapng.
#   2. nfgen — the optional nfdump test-record generator, if installed, given via
#      NFGEN_BIN, or bundled as a Linux ARM64 binary at ./.local-tools/nfgen.
#   3. Bash + nfcapd FALLBACK — fully portable: craft one synthetic NetFlow v5
#      datagram in pure Bash (5 records, 59 packets, 42,128 bytes; TCP=3/UDP=1/
#      ICMP=1), send it to a short-lived local nfcapd collector over UDP, and
#      keep the resulting non-empty nfdump file. No Python/Perl, no packet
#      capture, no payloads, no downloads.
#
# OUTPUT
#   * PCAP method : DEST/<pcap-basename>/nfcapd.*  (one subdir per capture, so
#                   multiple captures never overwrite each other). DEST defaults
#                   to RAW_DIR (raw/). Each converted file is verified readable
#                   by nfdump and its record count is printed.
#   * Synthetic   : RAW_DIR/2026-01/2026-01-01/nfcapd.202601010000
#                   (a fixed, documented sample path).
#   Existing non-empty synthetic targets are never overwritten.
#
# WORKFLOW
#   detect inputs -> pick method -> generate/convert -> verify with nfdump ->
#   report where files landed. Next step is ./anonymize_flows.sh.
#
# USAGE
#   ./make_sample_data.sh                          # synthetic (nfgen, else nfcapd)
#   ./make_sample_data.sh capture.pcap             # convert one capture
#   ./make_sample_data.sh a.pcap b.pcapng c.pcap   # convert several captures
#   ./make_sample_data.sh /path/to/pcap_dir        # convert every *.pcap/*.pcapng in a dir
#   PCAP="a.pcap b.pcap" ./make_sample_data.sh     # same, via environment
#   DEST=raw/captured ./make_sample_data.sh a.pcap # choose the output root
#
# ENVIRONMENT OVERRIDES
#   RAW_DIR (raw)   DEST (output root for the pcap method; defaults to RAW_DIR)
#   PCAP (space-separated capture list)   COLLECT_PORT (29995, nfcapd fallback)
#   NFGEN_BIN (path to an nfgen binary)   TMPDIR
#   NOTE: DEST is now environment-only; every positional argument is treated as
#         a capture input so that multiple captures can be passed at once.
#
# REQUIRES: nfdump; plus nfpcapd (pcap method) or nfcapd (fallback). Bash only.
# ============================================================================
set -euo pipefail

RAW_DIR="${RAW_DIR:-raw}"
DEST="${DEST:-$RAW_DIR}"
COLLECT_PORT="${COLLECT_PORT:-29995}"
FALLBACK_TARGET="2026-01/2026-01-01/nfcapd.202601010000"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NFGEN_BIN="${NFGEN_BIN:-}"

case "${1:-}" in
  -h|--help)
    grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | sed -n '1,50p'
    exit 0
    ;;
esac

# Gather capture inputs: positional args take precedence over the PCAP env var.
declare -a PCAP_INPUTS=()
if [[ $# -gt 0 ]]; then
  PCAP_INPUTS=("$@")
elif [[ -n "${PCAP:-}" ]]; then
  read -r -a PCAP_INPUTS <<< "$PCAP"
fi

die() { echo "ERROR: $*" >&2; exit 1; }
flow_count() {
  # nfgen leaves its summary counters at zero, so count the records nfdump can
  # actually export instead of trusting `nfdump -I`.
  nfdump -q -N -r "$1" -o 'fmt:%cnt' 2>/dev/null |
    awk 'NF { count++ } END { print count + 0 }' || true
}

# ---- method 1: convert one or more user-provided pcaps with nfpcapd ---------
generate_with_pcap() {
  command -v nfpcapd >/dev/null 2>&1 || die "nfpcapd not found. Install the nfdump suite: sudo apt-get install nfdump"
  command -v nfdump  >/dev/null 2>&1 || die "nfdump is required to verify the converted output."

  # Expand inputs: files as-is; directories -> their *.pcap/*.pcapng contents.
  local -a pcaps=()
  local item p
  for item in "${PCAP_INPUTS[@]}"; do
    if [[ -d "$item" ]]; then
      while IFS= read -r -d '' p; do pcaps+=("$p"); done \
        < <(find "$item" -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print0)
    elif [[ -f "$item" ]]; then
      pcaps+=("$item")
    else
      die "pcap input not found: '$item' (pass .pcap/.pcapng files or a directory of them)."
    fi
  done
  (( ${#pcaps[@]} > 0 )) || die "no .pcap/.pcapng files found in the given input(s)."

  local grand_total=0 pcap base out_dir total f flows
  local -a files
  for pcap in "${pcaps[@]}"; do
    base="$(basename -- "$pcap")"; base="${base%.*}"
    out_dir="$DEST/$base"
    mkdir -p "$out_dir"
    echo "Converting '$pcap' -> nfcapd files under '$out_dir' ..."
    nfpcapd -r "$pcap" -w "$out_dir"

    shopt -s nullglob
    files=("$out_dir"/nfcapd.*)
    shopt -u nullglob
    (( ${#files[@]} > 0 )) || die "no nfcapd.* files were produced for '$pcap' — check the nfpcapd output above."

    total=0
    for f in "${files[@]}"; do
      flows="$(flow_count "$f")"
      total=$(( total + ${flows:-0} ))
      echo "  $f ($flows records)"
    done
    (( total > 0 )) || die "converted files for '$pcap' contain no readable flows."
    grand_total=$(( grand_total + total ))
    echo "  -> ${#files[@]} file(s), $total record(s) under $out_dir"
  done
  echo "Converted ${#pcaps[@]} pcap(s) into nfcapd files under $DEST/ ($grand_total total record(s))."
}

resolve_nfgen() {
  if [[ -n "$NFGEN_BIN" ]]; then
    [[ -x "$NFGEN_BIN" ]] || die "NFGEN_BIN is not executable: $NFGEN_BIN"
    return 0
  fi
  if command -v nfgen >/dev/null 2>&1; then
    NFGEN_BIN="$(command -v nfgen)"
    return 0
  fi
  # The persisted binary is Linux ARM64 and must not be selected on macOS.
  if [[ "$(uname -s)" == "Linux" && -x "$SCRIPT_DIR/.local-tools/nfgen" ]]; then
    NFGEN_BIN="$SCRIPT_DIR/.local-tools/nfgen"
    return 0
  fi
  return 1
}

generate_with_nfgen() {
  command -v nfdump >/dev/null 2>&1 || die "nfdump is required to verify nfgen output."
  local output="$RAW_DIR/$FALLBACK_TARGET"
  local work_dir generated flows

  if [[ -f "$output" ]]; then
    flows="$(flow_count "$output")"
    if [[ "${flows:-0}" -gt 0 ]]; then
      echo "sample already exists at $output ($flows records); refusing to overwrite it."
      return 0
    fi
    die "existing target has no readable flows: $output (move it aside and retry)"
  fi

  # nfgen is an upstream test binary, not a normal installed CLI. Version 1.7.3
  # accepts no output option and always creates ./test.flows.nf.
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nfgen-sample.XXXXXX")"
  echo "using nfgen: $NFGEN_BIN"
  if ! (cd "$work_dir" && "$NFGEN_BIN"); then
    rm -rf "$work_dir"
    die "nfgen failed"
  fi
  generated="$work_dir/test.flows.nf"
  [[ -f "$generated" ]] || { rm -rf "$work_dir"; die "nfgen did not create test.flows.nf"; }
  flows="$(flow_count "$generated")"
  if [[ "${flows:-0}" -le 0 ]]; then
    rm -rf "$work_dir"
    die "nfgen output contains no readable flows"
  fi

  mkdir -p "$(dirname "$output")"
  mv "$generated" "$output"
  rm -rf "$work_dir"
  echo "generated $output ($flows nfgen test records)"
  echo "verified by exporting $flows readable records with nfdump"
}

# PAYLOAD holds printable \xHH escapes. Keeping the encoded packet in a Bash
# variable avoids NUL-byte limitations; one final printf emits the whole UDP
# datagram in a single write.
PAYLOAD=""
append_byte() {
  local hex
  printf -v hex '%02x' "$(( $1 & 255 ))"
  PAYLOAD+="\\x$hex"
}
append_u16() {
  append_byte "$(( $1 >> 8 ))"
  append_byte "$1"
}
append_u32() {
  append_byte "$(( $1 >> 24 ))"
  append_byte "$(( $1 >> 16 ))"
  append_byte "$(( $1 >> 8 ))"
  append_byte "$1"
}
append_ipv4() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  append_byte "$a"; append_byte "$b"; append_byte "$c"; append_byte "$d"
}

append_record() { # src dst src-port dst-port protocol packets bytes flags index
  local src="$1" dst="$2" src_port="$3" dst_port="$4" protocol="$5"
  local packets="$6" bytes="$7" flags="$8" index="$9"
  append_ipv4 "$src"
  append_ipv4 "$dst"
  append_ipv4 "203.0.113.1"       # next hop (RFC 5737 documentation range)
  append_u16 1                     # input interface
  append_u16 2                     # output interface
  append_u32 "$packets"
  append_u32 "$bytes"
  append_u32 "$((100 + index))"   # first-seen uptime
  append_u32 "$((200 + index))"   # last-seen uptime
  append_u16 "$src_port"
  append_u16 "$dst_port"
  append_byte 0                    # padding
  append_byte "$flags"            # TCP flags
  append_byte "$protocol"
  append_byte 0                    # ToS
  append_u16 64512                 # source AS
  append_u16 64513                 # destination AS
  append_byte 24                   # source mask
  append_byte 24                   # destination mask
  append_u16 0                     # padding
}

build_netflow_v5_packet() {
  local now
  now="$(date +%s)"
  PAYLOAD=""

  # NetFlow v5 header: version, count, uptime, UNIX time, sequence, engine,
  # and sampling interval.
  append_u16 5
  append_u16 5
  append_u32 1000
  append_u32 "$now"
  append_u32 0
  append_u32 1
  append_byte 0
  append_byte 0
  append_u16 0

  append_record "192.0.2.10" "198.51.100.20" 40000 443 6 18 14220 24 0
  append_record "192.0.2.11" "198.51.100.30" 40001 22  6 10 6200  2  1
  append_record "192.0.2.12" "198.51.100.40" 40002 53  17 4  512   0  2
  append_record "192.0.2.10" "198.51.100.50" 40003 80  6 25 21000 24 3
  append_record "192.0.2.13" "198.51.100.60" 0     0   1 2  196   0  4
}

generate_with_nfcapd() {
  command -v nfcapd >/dev/null 2>&1 || die "nfgen is absent and nfcapd is not installed. Install the nfdump package."
  command -v nfdump >/dev/null 2>&1 || die "nfdump is required to verify the generated sample."
  [[ -x /usr/bin/printf ]] || die "the coreutils /usr/bin/printf command is required for the binary UDP write"

  local output="$RAW_DIR/$FALLBACK_TARGET"
  local capture_dir capture_log collector_pid="" candidate flows valid_file=""
  if [[ -f "$output" ]]; then
    flows="$(flow_count "$output")"
    if [[ "${flows:-0}" -gt 0 ]]; then
      echo "sample already exists at $output ($flows records); refusing to overwrite it."
      return 0
    fi
    die "existing target has no readable flows: $output (move it aside and retry)"
  fi

  capture_dir="$(mktemp -d "${TMPDIR:-/tmp}/flow-sample.XXXXXX")"
  capture_log="$capture_dir/collector.log"
  cleanup() {
    if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
      kill -TERM "$collector_pid" 2>/dev/null || true
      wait "$collector_pid" 2>/dev/null || true
    fi
    rm -rf "$capture_dir"
  }
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT TERM

  echo "nfgen not found; using the built-in Bash + nfcapd fallback."
  nfcapd -w "$capture_dir" -p "$COLLECT_PORT" > "$capture_log" 2>&1 &
  collector_pid=$!
  sleep 1
  if ! kill -0 "$collector_pid" 2>/dev/null; then
    cat "$capture_log" >&2
    die "nfcapd failed to start on UDP port $COLLECT_PORT"
  fi

  build_netflow_v5_packet
  # Use the external, buffered printf. Bash's builtin may split binary output
  # into several write(2) calls, which UDP would treat as separate datagrams.
  if ! /usr/bin/printf '%b' "$PAYLOAD" > "/dev/udp/127.0.0.1/$COLLECT_PORT"; then
    die "could not send the synthetic NetFlow datagram to nfcapd"
  fi
  sleep 1
  kill -TERM "$collector_pid" 2>/dev/null || true
  wait "$collector_pid" 2>/dev/null || true
  collector_pid=""

  while IFS= read -r -d '' candidate; do
    flows="$(flow_count "$candidate")"
    if [[ "${flows:-0}" -gt 0 ]]; then
      valid_file="$candidate"
      break
    fi
  done < <(find "$capture_dir" -type f -name 'nfcapd.*' -print0)

  if [[ -z "$valid_file" ]]; then
    cat "$capture_log" >&2
    die "nfcapd did not create a non-empty flow file"
  fi

  mkdir -p "$(dirname "$output")"
  mv "$valid_file" "$output"
  echo "generated $output ($flows synthetic records)"
  echo "verified by exporting $flows readable records with nfdump"

  trap - EXIT INT TERM
  cleanup
}

# ---- dispatch: pcap(s) if provided > nfgen > nfcapd fallback ----------------
if [[ ${#PCAP_INPUTS[@]} -gt 0 ]]; then
  generate_with_pcap
elif resolve_nfgen; then
  generate_with_nfgen
else
  generate_with_nfcapd
fi
