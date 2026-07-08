#!/usr/bin/env bash
#
# anonymize_flows.sh — CIARA/FIU Flow Dataset Anonymization Prototype
#
# Anonymizes the IP fields in nfdump binary flow files using nfanon
# (prefix-preserving CryptoPAn), preserving the raw/ folder structure into
# anon/. Required non-IP field values are left identical, so downstream
# analysis (counts, ports, protocols, volumes, timing, TCP flags) is unchanged.
#
# Tools used:  nfanon (from the nfdump suite), coreutils.  Bash only.
#
# Safety:
#   * Defaults to DRY-RUN. You must pass --run to actually write files.
#   * The key is read from $NFANON_KEY or a local key file; it is NEVER printed,
#     logged, or committed (only a short fingerprint is shown).
#   * Original raw/ files are never modified.
#
# Usage:
#   ./anonymize_flows.sh                 # dry-run (default) using ./folders
#   ./anonymize_flows.sh --run           # actually anonymize
#   RAW_DIR=raw ANON_DIR=anon ./anonymize_flows.sh --run
#   NFANON_KEY=<32-char-or-0x-plus-64-hex> ./anonymize_flows.sh --run
#
set -euo pipefail

# ---- configuration (override via environment) ------------------------------
RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"
KEY_FILE="${KEY_FILE:-secret/anon.key}"
LOG_FILE="${LOG_FILE:-logs/anonymize.log}"
FILE_GLOB="${FILE_GLOB:-nfcapd.*}"
DRY_RUN=1

# ---- parse arguments -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)       DRY_RUN=0 ;;
    --dry-run)   DRY_RUN=1 ;;
    --key-file)  KEY_FILE="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 30; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "ERROR: $*" >&2; exit 1; }
timestamp() { date -Is 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'; }

command -v nfanon >/dev/null 2>&1 || \
  die "nfanon not found. Install the nfdump suite:  sudo apt-get install nfdump"

# ---- load the key (never printed) ------------------------------------------
if [[ -n "${NFANON_KEY:-}" ]]; then
  KEY="$NFANON_KEY"; KEY_SRC="environment variable NFANON_KEY"
elif [[ -f "$KEY_FILE" ]]; then
  KEY="$(cat "$KEY_FILE")"; KEY_SRC="key file $KEY_FILE"
else
  die "No key found. Set \$NFANON_KEY or create $KEY_FILE (see README: generate_key.sh)."
fi

# Validate and normalize the key shape. nfanon accepts either a literal
# 32-character key or 32 hex bytes prefixed with 0x. Older versions of this
# script generated the 64 hex digits without the prefix, so accept and repair
# that form in memory for backward compatibility.
klen=${#KEY}
if [[ "$KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || [[ $klen -eq 32 ]]; then
  :
elif [[ "$KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  KEY="0x$KEY"
else
  die "Key must be a 32-character string or 0x followed by 64 hex digits (got length $klen)."
fi
KEY_FPR="$(printf '%s' "$KEY" | sha256sum | cut -c1-12)"

# ---- start ----------------------------------------------------------------
mkdir -p "$(dirname "$LOG_FILE")"
{
  echo "==================================================================="
  echo "run started : $(timestamp)"
  echo "mode        : $([[ $DRY_RUN -eq 1 ]] && echo DRY-RUN || echo RUN)"
  echo "raw dir     : $RAW_DIR"
  echo "anon dir    : $ANON_DIR"
  echo "key source  : $KEY_SRC"
  echo "key sha256  : ${KEY_FPR} (fingerprint only — key never logged)"
  echo "==================================================================="
} | tee -a "$LOG_FILE"

[[ -f "$FOLDERS_FILE" ]] || die "folders file '$FOLDERS_FILE' not found."

declare -a input_files=()
listed_folders=0
preflight_ok=1

# Discover and validate every input before writing any anonymized output. This
# prevents a misspelled/empty folder list from looking like a successful run.
while IFS= read -r folder || [[ -n "$folder" ]]; do
  [[ -z "$folder" || "$folder" == \#* ]] && continue
  listed_folders=$((listed_folders + 1))
  src_root="$RAW_DIR/$folder"
  if [[ ! -d "$src_root" ]]; then
    echo "ERROR: listed input folder does not exist: $src_root" | tee -a "$LOG_FILE" >&2
    preflight_ok=0
    continue
  fi

  folder_files=0
  while IFS= read -r -d '' src; do
    input_files+=("$src")
    folder_files=$((folder_files + 1))
  done < <(find "$src_root" -type f -name "$FILE_GLOB" -print0)

  if [[ $folder_files -eq 0 ]]; then
    echo "ERROR: no '$FILE_GLOB' files found under $src_root" | tee -a "$LOG_FILE" >&2
    preflight_ok=0
  fi
done < "$FOLDERS_FILE"

if [[ $listed_folders -eq 0 ]]; then
  echo "ERROR: folders file '$FOLDERS_FILE' contains no input folders." | tee -a "$LOG_FILE" >&2
  preflight_ok=0
fi
if [[ ${#input_files[@]} -eq 0 ]]; then
  echo "ERROR: no input flow files were discovered; nothing was anonymized." | tee -a "$LOG_FILE" >&2
  preflight_ok=0
fi
if [[ $preflight_ok -ne 1 ]]; then
  echo "PRE-FLIGHT FAILED. Create the listed sample-data folders/files and retry." | tee -a "$LOG_FILE" >&2
  exit 1
fi

processed=0
for src in "${input_files[@]}"; do
  rel="${src#"$RAW_DIR"/}"          # path relative to raw/
  dst="$ANON_DIR/$rel"              # mirror into anon/
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] nfanon -K <hidden> -r $src -w $dst" | tee -a "$LOG_FILE"
  else
    mkdir -p "$(dirname "$dst")"
    nfanon -K "$KEY" -r "$src" -w "$dst"
    echo "anonymized: $src -> $dst" | tee -a "$LOG_FILE"
  fi
  processed=$((processed + 1))
done

echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"
if [[ $DRY_RUN -eq 1 ]]; then
  echo "DRY-RUN complete. $processed file(s) WOULD be anonymized. Re-run with --run." | tee -a "$LOG_FILE"
else
  echo "RUN complete. $processed file(s) anonymized into $ANON_DIR/." | tee -a "$LOG_FILE"
  echo "Next: ./validate_flows.sh" | tee -a "$LOG_FILE"
fi
