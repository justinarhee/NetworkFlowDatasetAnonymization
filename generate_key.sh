#!/usr/bin/env bash
#
# generate_key.sh — CIARA/FIU Flow Dataset Anonymization Prototype
# ============================================================================
# PURPOSE
#   Create (or rotate) the local CryptoPAn key that nfanon uses to pseudonymize
#   IP fields. The key is 32 random bytes rendered as "0x" + 64 hex digits — the
#   exact form anonymize_flows.sh and nfanon expect.
#
# INPUT
#   --force, -f   replace an existing key (rotates it). Without it, an existing
#                 key is kept and the script exits without change.
#   -h, --help    print this header.
#   KEY_FILE      environment override for the output path (default secret/anon.key).
#
# OUTPUT
#   Writes the key to $KEY_FILE with permissions 600 inside a 0700 secret dir,
#   and prints ONLY a short sha256 fingerprint of the key (safe to share); the
#   key itself is never printed. This fingerprint matches the one logged by
#   anonymize_flows.sh, so you can confirm both use the same key.
#
# SAFETY
#   NEVER commit, share, or document the key. secret/ and *.key must be
#   git-ignored. Rotate the key per release so each release uses a different,
#   uncorrelatable mapping.
#
# REQUIRES: coreutils (od, tr, sha256sum) and /dev/urandom. Bash only.
#           No OpenSSL is needed — randomness comes from /dev/urandom via od.
# ============================================================================
set -euo pipefail

KEY_FILE="${KEY_FILE:-secret/anon.key}"
FORCE=0
case "${1:-}" in
  --force|-f) FORCE=1 ;;
  -h|--help)  grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | sed -n '1,34p'; exit 0 ;;
  "")         : ;;
  *)          echo "Unknown option: $1" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$(dirname "$KEY_FILE")"

if [[ -f "$KEY_FILE" && $FORCE -eq 0 ]]; then
  echo "Key already exists at $KEY_FILE."
  echo "Re-run with --force to replace it (rotates the key)."
  exit 0
fi

# 32 random bytes -> 64 lowercase hex chars. nfanon requires the 0x prefix for
# this form. /dev/urandom is a cryptographically suitable source (no OpenSSL).
HEX_KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$HEX_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "ERROR: failed to generate 32 random bytes." >&2; exit 1; }

printf '0x%s\n' "$HEX_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"    # enforce perms even when rotating an existing file

echo "Wrote new key to $KEY_FILE (perms 600)."
echo "Fingerprint: $(printf '0x%s' "$HEX_KEY" | sha256sum | cut -c1-12)  (share this, never the key)"
