#!/usr/bin/env bash
# generate_key.sh — create a local anonymization key for nfanon.
# Produces a 64-hex-digit key (valid for nfanon -K), stored 0600, git-ignored.
# NEVER commit, share, or document this key.
set -euo pipefail
KEY_FILE="${KEY_FILE:-secret/anon.key}"

command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found." >&2; exit 1; }
mkdir -p "$(dirname "$KEY_FILE")"
FORCE=0
[[ "${1:-}" == "--force" || "${1:-}" == "-f" ]] && FORCE=1
if [[ -f "$KEY_FILE" && $FORCE -eq 0 ]]; then
  echo "Key already exists at $KEY_FILE."
  echo "Re-run with --force to replace it (rotates the key)."
  exit 0
fi

# Written WITHOUT a trailing newline so this
# fingerprint matches the one anonymize_flows.sh logs (which hashes the value
# read back with $(cat), i.e. newline-stripped).
key="0x$(openssl rand -hex 32)"      # 0x + 64 hex = the form nfanon requires
printf '%s' "$key" > "$KEY_FILE"
chmod 600 "$KEY_FILE"
echo "Wrote new key to $KEY_FILE (perms 600)."
echo "Fingerprint: $(printf '%s' "$key" | sha256sum | cut -c1-12)  (share this, never the key)"

