#!/usr/bin/env bash
#
# validate_flows.sh — compare raw and anonymized nfdump flow files.
#
# Validation is data-driven: it compares every required preserved field and
# derives the original address set from the raw records. A missing directory,
# zero discovered files, a missing output, or any failed nfdump command makes
# the run fail.
#
set -uo pipefail

RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"
FILE_GLOB="${FILE_GLOB:-nfcapd.*}"
REPORT="${REPORT:-logs/validation.txt}"

command -v nfdump >/dev/null 2>&1 || { echo "ERROR: nfdump not found." >&2; exit 1; }
mkdir -p "$(dirname "$REPORT")" || exit 1
: > "$REPORT" || exit 1
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/validate-flows.XXXXXX")" || exit 1
trap 'rm -rf "$TMP_DIR"' EXIT

overall_ok=1
log() { echo "$@" | tee -a "$REPORT"; }
pass() { log "  $1 [PASS]"; }
fail() { log "  $1 [FAIL]"; overall_ok=0; }

export_records() { # file format destination label
  local file="$1" format="$2" destination="$3" label="$4"
  if ! nfdump -q -N -6 -r "$file" -o "$format" > "$destination" 2>> "$REPORT"; then
    fail "$label: nfdump could not read/export $file"
    return 1
  fi
}

compare_files() { # label before after
  local label="$1" before="$2" after="$3"
  if cmp -s "$before" "$after"; then
    pass "$label: identical"
  else
    fail "$label: changed"
  fi
}

make_distribution() { # records column output
  awk -F, -v column="$2" '
    NF >= column { count[$column]++ }
    END { for (value in count) print value "," count[value] }
  ' "$1" | LC_ALL=C sort > "$3"
}

make_time_series() { # preserved records output
  awk -F, '
    NF >= 7 {
      minute = int($1 / 60)
      flows[minute]++
      packets[minute] += $6
      bytes[minute] += $7
    }
    END {
      for (minute in flows)
        print minute "," flows[minute] "," packets[minute] "," bytes[minute]
    }
  ' "$1" | LC_ALL=C sort -t, -k1,1n > "$2"
}

make_talker_vector() { # talker records address-column output
  awk -F, -v column="$2" '
    NF >= 4 {
      address = $column
      flows[address]++
      packets[address] += $3
      bytes[address] += $4
    }
    END {
      # Addresses deliberately omitted: compare the ranked traffic structure.
      for (address in flows)
        print bytes[address] "," packets[address] "," flows[address]
    }
  ' "$1" | LC_ALL=C sort -t, -k1,1nr -k2,2nr -k3,3nr > "$3"
}

make_address_set() { # IP-field records output
  awk -F, '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function usable(value) {
      value = trim(value)
      return value != "" && value != "0.0.0.0" && value != "::" &&
             value != "0:0:0:0:0:0:0:0" && value ~ /[.:]/
    }
    { for (i = 1; i <= NF; i++) if (usable($i)) print trim($i) }
  ' "$1" | LC_ALL=C sort -u > "$2"
}

check_mapping() { # raw IP rows anonymized IP rows diagnostics
  local raw_rows="$1" anon_rows="$2" diagnostics="$3"
  paste "$raw_rows" "$anon_rows" | awk -F '\t' '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function empty_address(value) {
      value = trim(value)
      return value == "" || value == "0.0.0.0" || value == "::" ||
             value == "0:0:0:0:0:0:0:0"
    }
    {
      raw_count = split($1, raw, ",")
      anon_count = split($2, anon, ",")
      if (raw_count != anon_count) {
        print "record " NR ": IP-field count differs"
        bad = 1
        next
      }
      for (i = 1; i <= raw_count; i++) {
        r = trim(raw[i]); a = trim(anon[i])
        if (empty_address(r) && empty_address(a)) continue
        if (empty_address(r) != empty_address(a)) {
          print "record " NR ", IP field " i ": address presence differs"
          bad = 1
          continue
        }
        if (r == a) {
          print "record " NR ", IP field " i ": original address remains visible"
          bad = 1
        }
        if ((r in forward) && forward[r] != a) {
          print "record " NR ", IP field " i ": inconsistent pseudonym"
          bad = 1
        }
        if ((a in reverse) && reverse[a] != r) {
          print "record " NR ", IP field " i ": pseudonym collision"
          bad = 1
        }
        forward[r] = a
        reverse[a] = r
      }
    }
    END { exit bad ? 1 : 0 }
  ' > "$diagnostics"
}

if [[ ! -f "$FOLDERS_FILE" ]]; then
  fail "folders file not found: $FOLDERS_FILE"
  log "OVERALL: FAIL — validation did not run"
  exit 1
fi

declare -a input_files=()
listed_folders=0
while IFS= read -r folder || [[ -n "$folder" ]]; do
  [[ -z "$folder" || "$folder" == \#* ]] && continue
  listed_folders=$((listed_folders + 1))
  src_root="$RAW_DIR/$folder"
  if [[ ! -d "$src_root" ]]; then
    fail "listed input folder does not exist: $src_root"
    continue
  fi

  folder_files=0
  while IFS= read -r -d '' src; do
    input_files+=("$src")
    folder_files=$((folder_files + 1))
  done < <(find "$src_root" -type f -name "$FILE_GLOB" -print0)
  [[ $folder_files -gt 0 ]] || fail "no '$FILE_GLOB' files found under $src_root"
done < "$FOLDERS_FILE"

[[ $listed_folders -gt 0 ]] || fail "folders file contains no input folders: $FOLDERS_FILE"
if [[ ${#input_files[@]} -eq 0 ]]; then
  fail "no input flow files discovered; zero-file validation is not a pass"
  log "==================================================================="
  log "OVERALL: FAIL — no flow files were validated"
  log "report written to $REPORT"
  exit 1
fi

log "input files discovered: ${#input_files[@]}"
files_checked=0
file_index=0
: > "$TMP_DIR/all.raw.talkers"
: > "$TMP_DIR/all.anon.talkers"
: > "$TMP_DIR/all.raw.ips"
: > "$TMP_DIR/all.anon.ips"

for src in "${input_files[@]}"; do
  file_index=$((file_index + 1))
  rel="${src#"$RAW_DIR"/}"
  dst="$ANON_DIR/$rel"
  prefix="$TMP_DIR/file-$file_index"
  log "==================================================================="
  log "file: $rel"

  if [[ ! -f "$dst" ]]; then
    fail "missing anonymized file: $dst"
    continue
  fi

  # Exact record-level comparison of every field the assignment requires us
  # to preserve. Epoch timestamps avoid locale/formatting differences.
  if ! export_records "$src" 'fmt:%tsr,%ter,%pr,%sp,%dp,%pkt,%byt,%flg' "$prefix.raw.preserved" "preserved-field export"; then
    continue
  fi
  if ! export_records "$dst" 'fmt:%tsr,%ter,%pr,%sp,%dp,%pkt,%byt,%flg' "$prefix.anon.preserved" "preserved-field export"; then
    continue
  fi
  if [[ ! -s "$prefix.raw.preserved" ]]; then
    fail "input contains zero readable flow records"
    continue
  fi

  raw_summary="$(awk -F, '{ flows++; packets += $6; bytes += $7 } END { print "flows=" flows ", packets=" packets ", bytes=" bytes }' "$prefix.raw.preserved")"
  anon_summary="$(awk -F, '{ flows++; packets += $6; bytes += $7 } END { print "flows=" flows ", packets=" packets ", bytes=" bytes }' "$prefix.anon.preserved")"
  log "  BEFORE: $raw_summary"
  log "  AFTER : $anon_summary"
  compare_files "record count and packet/byte totals" <(printf '%s\n' "$raw_summary") <(printf '%s\n' "$anon_summary")
  compare_files "all preserved record fields (time/protocol/ports/packets/bytes/TCP flags)" "$prefix.raw.preserved" "$prefix.anon.preserved"

  for spec in 'packet distribution:6' 'byte distribution:7' 'protocol distribution:3' 'source-port distribution:4' 'destination-port distribution:5'; do
    label="${spec%%:*}"
    column="${spec##*:}"
    make_distribution "$prefix.raw.preserved" "$column" "$prefix.raw.distribution"
    make_distribution "$prefix.anon.preserved" "$column" "$prefix.anon.distribution"
    compare_files "$label" "$prefix.raw.distribution" "$prefix.anon.distribution"
  done

  make_time_series "$prefix.raw.preserved" "$prefix.raw.timeseries"
  make_time_series "$prefix.anon.preserved" "$prefix.anon.timeseries"
  compare_files "per-minute time-series flow/packet/byte volume" "$prefix.raw.timeseries" "$prefix.anon.timeseries"

  if ! export_records "$src" 'fmt:%sa,%da,%pkt,%byt' "$prefix.raw.talkers" "top-talker export"; then continue; fi
  if ! export_records "$dst" 'fmt:%sa,%da,%pkt,%byt' "$prefix.anon.talkers" "top-talker export"; then continue; fi
  cat "$prefix.raw.talkers" >> "$TMP_DIR/all.raw.talkers"
  cat "$prefix.anon.talkers" >> "$TMP_DIR/all.anon.talkers"

  # Cover source, destination, IP next-hop, BGP next-hop, and router/exporter.
  if ! export_records "$src" 'fmt:%sa,%da,%nh,%nhb,%ra' "$prefix.raw.ips" "IP-field export"; then continue; fi
  if ! export_records "$dst" 'fmt:%sa,%da,%nh,%nhb,%ra' "$prefix.anon.ips" "IP-field export"; then continue; fi
  cat "$prefix.raw.ips" >> "$TMP_DIR/all.raw.ips"
  cat "$prefix.anon.ips" >> "$TMP_DIR/all.anon.ips"

  files_checked=$((files_checked + 1))
done

log "==================================================================="
log "dataset-wide checks"
if [[ $files_checked -eq 0 ]]; then
  fail "dataset-wide checks could not run because no file pair was readable"
else
  for spec in 'source top-talker structure:1' 'destination top-talker structure:2'; do
    label="${spec%%:*}"
    column="${spec##*:}"
    make_talker_vector "$TMP_DIR/all.raw.talkers" "$column" "$TMP_DIR/all.raw.talker-vector"
    make_talker_vector "$TMP_DIR/all.anon.talkers" "$column" "$TMP_DIR/all.anon.talker-vector"
    compare_files "$label" "$TMP_DIR/all.raw.talker-vector" "$TMP_DIR/all.anon.talker-vector"
  done

  make_address_set "$TMP_DIR/all.raw.ips" "$TMP_DIR/all.raw.address-set"
  make_address_set "$TMP_DIR/all.anon.ips" "$TMP_DIR/all.anon.address-set"
  comm -12 "$TMP_DIR/all.raw.address-set" "$TMP_DIR/all.anon.address-set" > "$TMP_DIR/visible-addresses"
  if [[ -s "$TMP_DIR/visible-addresses" ]]; then
    fail "one or more original IP addresses remain visible anywhere in the output dataset"
  else
    pass "all original IP addresses were replaced (data-driven IPv4/IPv6 check)"
  fi

  if check_mapping "$TMP_DIR/all.raw.ips" "$TMP_DIR/all.anon.ips" "$TMP_DIR/mapping-errors"; then
    pass "IP pseudonyms are changed, deterministic, and collision-free across the dataset"
  else
    fail "IP pseudonym mapping is invalid"
    sed 's/^/    /' "$TMP_DIR/mapping-errors" | tee -a "$REPORT" >/dev/null
  fi
fi

log "files checked: $files_checked/${#input_files[@]}"
if [[ $files_checked -ne ${#input_files[@]} ]]; then overall_ok=0; fi
if [[ $overall_ok -eq 1 ]]; then
  log "OVERALL: PASS — required utility preserved and all IP fields pseudonymized"
else
  log "OVERALL: FAIL — see checks above"
fi
log "report written to $REPORT"
[[ $overall_ok -eq 1 ]]
