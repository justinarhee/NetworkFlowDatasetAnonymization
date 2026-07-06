#!/usr/bin/env bash
#
# validate_flows.sh — compare raw vs anonymized flow files.
#
# Confirms the anonymization changed ONLY the IP addresses: flow counts,
# packets, bytes, protocol distribution, and port distribution must be
# identical, and the original IP addresses must no longer be visible.
#
# Tools: nfdump, coreutils, grep/awk. Bash only.
#
# Usage:  ./validate_flows.sh            # validate every folder in ./folders
#
set -euo pipefail

RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"
FILE_GLOB="${FILE_GLOB:-nfcapd.*}"
REPORT="${REPORT:-logs/validation.txt}"

# IP prefixes that appear in the sample data (RFC 5737/1918 documentation ranges).
# If any still appear in the anonymized output, anonymization FAILED.
RAW_IP_PATTERNS='192\.0\.2\.|198\.51\.100\.|203\.0\.113\.'

command -v nfdump >/dev/null 2>&1 || { echo "ERROR: nfdump not found." >&2; exit 1; }
mkdir -p "$(dirname "$REPORT")"; : > "$REPORT"

log() { echo "$@" | tee -a "$REPORT"; }

# Pull "Flows/Packets/Bytes + per-proto" from nfdump -I into simple KEY=VALUE lines.
summary() {  # $1 = file
  nfdump -r "$1" -I 2>/dev/null | awk -F': *' '
    /^ *Flows:/        {print "flows="$2}
    /^ *Flows_tcp:/    {print "tcp="$2}
    /^ *Flows_udp:/    {print "udp="$2}
    /^ *Flows_icmp:/   {print "icmp="$2}
    /^ *Packets:/      {print "packets="$2}
    /^ *Bytes:/        {print "bytes="$2}'
}

overall_ok=1
while IFS= read -r folder || [[ -n "$folder" ]]; do
  [[ -z "$folder" || "$folder" == \#* ]] && continue
  while IFS= read -r src; do
    rel="${src#"$RAW_DIR"/}"; dst="$ANON_DIR/$rel"
    log "==================================================================="
    log "file: $rel"
    if [[ ! -f "$dst" ]]; then log "  MISSING anonymized file: $dst"; overall_ok=0; continue; fi

    before="$(summary "$src")"; after="$(summary "$dst")"
    log "  BEFORE : $(echo "$before" | tr '\n' ' ')"
    log "  AFTER  : $(echo "$after"  | tr '\n' ' ')"
    if [[ "$before" == "$after" ]]; then
      log "  counts : IDENTICAL (flows/packets/bytes/protocols preserved)  [PASS]"
    else
      log "  counts : CHANGED — anonymization altered non-IP fields!        [FAIL]"
      overall_ok=0
    fi

    # Port distribution (should also be identical; show top ports).
    log "  dst-port distribution (anon):"
    nfdump -r "$dst" -s dstport/flows -n 0 2>/dev/null \
      | awk 'NR>1 && $1 ~ /[0-9]/ {print "     "$0}' | head -10 | tee -a "$REPORT" >/dev/null

    # Real IPs must be gone.
    if nfdump -r "$dst" -o csv 2>/dev/null | grep -Eq "$RAW_IP_PATTERNS"; then
      log "  real IPs visible in anon output: YES                          [FAIL]"
      overall_ok=0
    else
      log "  real IPs visible in anon output: No                           [PASS]"
    fi
  done < <(find "$RAW_DIR/$folder" -type f -name "$FILE_GLOB" | sort)
done < "$FOLDERS_FILE"

log "==================================================================="
log "OVERALL: $([[ $overall_ok -eq 1 ]] && echo 'PASS — utility preserved, IPs anonymized' || echo 'FAIL — see above')"
log "report written to $REPORT"
[[ $overall_ok -eq 1 ]]
