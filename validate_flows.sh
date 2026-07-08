#!/usr/bin/env bash
#
# validate_flows.sh — compare raw vs anonymized flow files.
#
# Confirms nfanon changed ONLY the IP addresses: flow count, packets, bytes,
# protocol distribution, and destination-port distribution must be identical
# before and after, and none of the original IP addresses may remain in the
# anonymized output.
#
# All measurements are computed from `nfdump -o fmt` output (which this script
# fully controls) rather than by scraping a fixed report layout, so it does not
# silently pass when parsing fails.
#
# Tools: nfdump, coreutils (awk/sort/comm/tr). Bash only.
#
# Usage:  ./validate_flows.sh
#
set -euo pipefail

RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"
FILE_GLOB="${FILE_GLOB:-nfcapd.*}"
REPORT="${REPORT:-logs/validation.txt}"

command -v nfdump >/dev/null 2>&1 || { echo "ERROR: nfdump not found." >&2; exit 1; }
mkdir -p "$(dirname "$REPORT")"; : > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

# flows / packets / bytes / per-protocol counts, computed from flow records and
# normalized (sorted) so the before/after strings compare deterministically.
# -q suppresses header+summary; -N prints plain (unscaled) integers to sum.
stats() {  # $1 = flow file
  nfdump -r "$1" -q -N -o 'fmt:%pr %pkt %byt' 2>/dev/null | awk '
    NF>=3 { flows++; pkts+=$2; bytes+=$3; proto[$1]++ }
    END {
      printf "bytes %d\n",   bytes+0
      printf "flows %d\n",   flows+0
      printf "packets %d\n", pkts+0
      for (p in proto) printf "proto_%s %d\n", p, proto[p]
    }' | sort
}

# destination-port distribution (flows per port), numerically sorted.
ports() {  # $1 = flow file
  nfdump -r "$1" -q -N -o 'fmt:%dp' 2>/dev/null \
    | awk 'NF { c[$1]++ } END { for (p in c) printf "%s %d\n", p, c[p] }' | sort -n
}

# sorted unique set of every IP (source and destination) in a file.
ips() {  # $1 = flow file
  nfdump -r "$1" -q -N -o 'fmt:%sa %da' 2>/dev/null \
    | tr -s ' ' '\n' | grep -E '[0-9]' | sort -u
}

overall_ok=1
while IFS= read -r folder || [[ -n "$folder" ]]; do
  [[ -z "$folder" || "$folder" == \#* ]] && continue
  while IFS= read -r src; do
    rel="${src#"$RAW_DIR"/}"; dst="$ANON_DIR/$rel"
    log "==================================================================="
    log "file: $rel"
    if [[ ! -f "$dst" ]]; then
      log "  MISSING anonymized file: $dst                                 [FAIL]"
      overall_ok=0; continue
    fi

    before="$(stats "$src" || true)"
    after="$(stats "$dst" || true)"

    # Guard: awk's END block prints "flows 0" even for zero input, so a mere
    # "flows" line is not proof of a successful read. Require flows > 0, else
    # FAIL loudly (never a silent pass on an unreadable/empty file).
    before_flows="$(awk '/^flows /{print $2+0; exit}' <<<"$before")"
    if [[ "${before_flows:-0}" -eq 0 ]]; then
      log "  ERROR: read 0 flows from $src — unreadable or empty nfcapd file"
      log "         (try:  nfdump -r \"$src\" -I  to inspect it directly)"
      overall_ok=0; continue
    fi

    log "  BEFORE : $(echo "$before" | tr '\n' ' ')"
    log "  AFTER  : $(echo "$after"  | tr '\n' ' ')"
    if [[ "$before" == "$after" ]]; then
      log "  counts : IDENTICAL (flows/packets/bytes/protocols preserved)  [PASS]"
    else
      log "  counts : CHANGED — anonymization altered non-IP fields!        [FAIL]"
      overall_ok=0
    fi

    # Destination-port distribution must also be identical.
    if [[ "$(ports "$src" || true)" == "$(ports "$dst" || true)" ]]; then
      log "  ports  : destination-port distribution preserved              [PASS]"
    else
      log "  ports  : destination-port distribution CHANGED                [FAIL]"
      overall_ok=0
    fi
    log "  dst ports (before): $(ports "$src" | tr '\n' ' ')"

    # No original IP may survive into the anonymized output. Compare the actual
    # IP sets (works for any address ranges present, not just hard-coded ones).
    orig_ips="$(ips "$src" || true)"
    anon_ips="$(ips "$dst" || true)"
    leaked="$(comm -12 <(printf '%s\n' "$orig_ips") <(printf '%s\n' "$anon_ips") | grep -E '[0-9]' || true)"
    if [[ -n "$leaked" ]]; then
      log "  IPs    : original address(es) STILL VISIBLE: $(echo "$leaked" | tr '\n' ' ')  [FAIL]"
      overall_ok=0
    else
      log "  IPs    : no original IP addresses remain in anon output        [PASS]"
    fi
  done < <(find "$RAW_DIR/$folder" -type f -name "$FILE_GLOB" | sort)
done < "$FOLDERS_FILE"

log "==================================================================="
if [[ $overall_ok -eq 1 ]]; then
  log "OVERALL: PASS — utility preserved, IPs anonymized"
else
  log "OVERALL: FAIL — see above"
fi
log "report written to $REPORT"
[[ $overall_ok -eq 1 ]]
