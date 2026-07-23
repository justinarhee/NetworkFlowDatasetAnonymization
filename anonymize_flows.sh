#!/usr/bin/env bash
#
# anonymize_flows.sh — CIARA/FIU Flow Dataset Anonymization Prototype
# ============================================================================
# PURPOSE
#   Pseudonymize the IP fields of nfdump binary flow files using nfanon
#   (CryptoPAn, prefix-preserving), writing the results into a separate anon/
#   tree that mirrors raw/. Every non-IP field (time, protocol, ports, packet
#   and byte counts, TCP flags) is left identical, so downstream traffic 
#   analysis is unaffected. The original raw/ files are never modified.
#
# INPUT (which files get processed) — resolved in this priority order:
#   1. PATH TARGET(S) given on the command line (files or directories). Only
#      those are processed. A target may be a single nfcapd file, a day dir,
#      a month dir, or any directory; directories are searched recursively for
#      "$FILE_GLOB".
#   2. THE FOLDERS FILE ("$FOLDERS_FILE"), if it exists and has content. Each
#      non-blank, non-"#" line names a folder under raw/ to process recursively.
#      This is the default scope / allowlist for a whole-dataset run.
#   3. THE ENTIRE raw/ TREE, if no targets are given and no folders file exists.
#
# OUTPUT
#   For each input raw/<rel>/nfcapd.* -> anon/<rel>/nfcapd.* (structure mirrored).
#   Targets outside raw/ are placed under anon/ by their file basename.
#   A run header + one line per file is appended to "$LOG_FILE". Only a short
#   sha256 fingerprint of the key is logged; the key itself is NEVER printed.
#
# PROCESS / WORKFLOW
#   parse args -> load & validate key -> discover input files (per priority
#   above) -> PRE-FLIGHT (fail if a listed folder/target is missing or empty)
#   -> for each file run: nfanon -K <key> -r <in> -w <out>. Existing anon/
#   outputs are skipped unless --force, so re-runs don't redo finished work.
#
# SAFETY
#   * Defaults to DRY-RUN; you must pass --run to write any files.
#   * Key is read from $NFANON_KEY or a local key file; never logged/committed.
#   * raw/ inputs are only read, never altered.
#
# USAGE
#   ./anonymize_flows.sh                          # dry-run, default scope (folders/raw)
#   ./anonymize_flows.sh --run                    # anonymize the default scope
#   ./anonymize_flows.sh raw/2026-01/2026-01-02   # dry-run just that one day
#   ./anonymize_flows.sh --run raw/2026-01/2026-01-02/nfcapd.202601020000   # one file
#   ./anonymize_flows.sh --run --force            # re-anonymize even if anon/ exists
#   ./anonymize_flows.sh --run --key-file secret/other.key
#   RAW_DIR=raw ANON_DIR=anon FILE_GLOB='nfcapd.*' ./anonymize_flows.sh --run
#   NFANON_KEY=<32-char | 0x+64hex> ./anonymize_flows.sh --run
#
# OPTIONS
#   --run              actually write anonymized files (default is dry-run)
#   --dry-run          force dry-run (default)
#   --force, -f        overwrite anon/ outputs that already exist
#   --key-file PATH    read the key from PATH instead of $KEY_FILE
#   -h, --help         print this header
#
# REQUIRES: nfanon (nfdump suite), coreutils. Bash only.
# ============================================================================
set -euo pipefail

# ---- configuration (override via environment) ------------------------------
RAW_DIR="${RAW_DIR:-raw}"
ANON_DIR="${ANON_DIR:-anon}"
FOLDERS_FILE="${FOLDERS_FILE:-folders}"
KEY_FILE="${KEY_FILE:-secret/anon.key}"
LOG_FILE="${LOG_FILE:-logs/anonymize.log}"
FILE_GLOB="${FILE_GLOB:-nfcapd.*}"
DRY_RUN=1
FORCE=0
declare -a CLI_TARGETS=()

# ---- parse arguments -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)      DRY_RUN=0 ;;
    --dry-run)  DRY_RUN=1 ;;
    --force|-f) FORCE=1 ;;
    --key-file) [[ $# -ge 2 ]] || { echo "ERROR: --key-file needs a path" >&2; exit 2; }
                KEY_FILE="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | sed -n '1,60p'; exit 0 ;;
    --)         shift; while [[ $# -gt 0 ]]; do CLI_TARGETS+=("$1"); shift; done; break ;;
    -*)         echo "Unknown option: $1" >&2; exit 2 ;;
    *)          CLI_TARGETS+=("$1") ;;
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

# Validate/normalize the key shape. nfanon accepts a literal 32-character key or
# 32 hex bytes prefixed with 0x. A legacy unprefixed 64-hex key is repaired in
# memory for backward compatibility. The key value is never echoed.
klen=${#KEY}
if [[ "$KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || [[ $klen -eq 32 ]]; then
  :
elif [[ "$KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  KEY="0x$KEY"
else
  die "Key must be a plain 32-character string or a 0x-prefixed 64-hex-digit key (e.g. 0x…)."
fi
KEY_FPR="$(printf '%s' "$KEY" | sha256sum | cut -c1-12)"

# ---- discover input files (priority: CLI targets > folders file > raw tree) -
mkdir -p "$(dirname "$LOG_FILE")"
declare -a input_files=()
preflight_ok=1
scope_desc=""

# Append every "$FILE_GLOB" file found at a path (a file is taken directly,
# a directory is searched recursively). Returns non-zero only if the path does
# not exist; an existing-but-empty directory is reported by the caller.
add_files_from_path() {
  local p="$1"
  if [[ -f "$p" ]]; then
    input_files+=("$p")
  elif [[ -d "$p" ]]; then
    while IFS= read -r -d '' f; do input_files+=("$f"); done \
      < <(find "$p" -type f -name "$FILE_GLOB" -print0)
  else
    echo "ERROR: target not found: $p" | tee -a "$LOG_FILE" >&2
    return 1
  fi
  return 0
}

if [[ ${#CLI_TARGETS[@]} -gt 0 ]]; then
  scope_desc="command-line target(s): ${CLI_TARGETS[*]}"
  for t in "${CLI_TARGETS[@]}"; do
    before=${#input_files[@]}
    add_files_from_path "$t" || preflight_ok=0
    if [[ -d "$t" && ${#input_files[@]} -eq $before ]]; then
      echo "ERROR: no '$FILE_GLOB' files found under target: $t" | tee -a "$LOG_FILE" >&2
      preflight_ok=0
    fi
  done
elif [[ -f "$FOLDERS_FILE" ]] && grep -qvE '^[[:space:]]*(#|$)' "$FOLDERS_FILE"; then
  scope_desc="folders file: $FOLDERS_FILE"
  while IFS= read -r folder || [[ -n "$folder" ]]; do
    [[ -z "$folder" || "$folder" == \#* ]] && continue
    src_root="$RAW_DIR/$folder"
    if [[ ! -d "$src_root" ]]; then
      echo "ERROR: listed input folder does not exist: $src_root" | tee -a "$LOG_FILE" >&2
      preflight_ok=0; continue
    fi
    before=${#input_files[@]}
    add_files_from_path "$src_root" || preflight_ok=0
    if [[ ${#input_files[@]} -eq $before ]]; then
      echo "ERROR: no '$FILE_GLOB' files found under $src_root" | tee -a "$LOG_FILE" >&2
      preflight_ok=0
    fi
  done < "$FOLDERS_FILE"
else
  scope_desc="entire $RAW_DIR tree (no CLI targets, no non-empty folders file)"
  [[ -d "$RAW_DIR" ]] || die "raw directory '$RAW_DIR' not found and no targets were given."
  add_files_from_path "$RAW_DIR" || preflight_ok=0
fi

# ---- run header ------------------------------------------------------------
{
  echo "==================================================================="
  echo "run started : $(timestamp)"
  echo "mode        : $([[ $DRY_RUN -eq 1 ]] && echo DRY-RUN || echo RUN)"
  echo "scope       : $scope_desc"
  echo "raw dir     : $RAW_DIR"
  echo "anon dir    : $ANON_DIR"
  echo "force       : $([[ $FORCE -eq 1 ]] && echo yes || echo no)"
  echo "key source  : $KEY_SRC"
  echo "key sha256  : ${KEY_FPR} (fingerprint only — key never logged)"
  echo "files found : ${#input_files[@]}"
  echo "==================================================================="
} | tee -a "$LOG_FILE"

if [[ ${#input_files[@]} -eq 0 ]]; then
  echo "ERROR: no input flow files were discovered; nothing was anonymized." | tee -a "$LOG_FILE" >&2
  preflight_ok=0
fi
if [[ $preflight_ok -ne 1 ]]; then
  echo "PRE-FLIGHT FAILED. Fix the target/folder list (or generate sample data) and retry." | tee -a "$LOG_FILE" >&2
  exit 1
fi

# ---- anonymize -------------------------------------------------------------
processed=0
skipped=0
for src in "${input_files[@]}"; do
  if [[ "$src" == "$RAW_DIR/"* ]]; then
    rel="${src#"$RAW_DIR"/}"          # mirror the path under raw/
  else
    rel="$(basename "$src")"          # target outside raw/: keep only the filename
  fi
  dst="$ANON_DIR/$rel"

  if [[ -s "$dst" && $FORCE -eq 0 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "[dry-run][skip] $dst already exists (use --force to overwrite)" | tee -a "$LOG_FILE"
    else
      echo "[skip] already anonymized: $dst (use --force to overwrite)" | tee -a "$LOG_FILE"
    fi
    skipped=$((skipped + 1)); continue
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] nfanon -K <hidden> -r $src -w $dst" | tee -a "$LOG_FILE"
  else
    mkdir -p "$(dirname "$dst")"
    nfanon -K "$KEY" -r "$src" -w "$dst"
    echo "anonymized: $src -> $dst" | tee -a "$LOG_FILE"
  fi
  processed=$((processed + 1))
done

# ---- summary ---------------------------------------------------------------
echo "-------------------------------------------------------------------" | tee -a "$LOG_FILE"
if [[ $DRY_RUN -eq 1 ]]; then
  echo "DRY-RUN complete. $processed file(s) WOULD be anonymized, $skipped skipped. Re-run with --run." | tee -a "$LOG_FILE"
else
  echo "RUN complete. $processed file(s) anonymized into $ANON_DIR/, $skipped skipped." | tee -a "$LOG_FILE"
fi
