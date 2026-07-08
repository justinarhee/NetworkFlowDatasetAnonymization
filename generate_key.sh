#!/usr/bin/env bash
# generate_key.sh — create a local anonymization key for nfanon.
# Produces an nfanon key as 0x + 64 hex digits, stored 0600, git-ignored.
# NEVER commit, share, or document this key.
set -euo pipefail
KEY_FILE="${KEY_FILE:-secret/anon.key}"
umask 077
mkdir -p "$(dirname "$KEY_FILE")"
if [[ -f "$KEY_FILE" ]]; then
  echo "Key already exists at $KEY_FILE (refusing to overwrite)."; exit 0
fi
# 32 random bytes -> 64 hex chars. nfanon requires the 0x prefix for this form.
# od and /dev/urandom are available in a minimal Ubuntu environment, avoiding
# an otherwise unnecessary OpenSSL package dependency.
HEX_KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$HEX_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Failed to generate 32 random bytes." >&2; exit 1; }
printf '0x%s\n' "$HEX_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"
echo "Wrote new key to $KEY_FILE (perms 600)."
echo "Fingerprint: $(printf '0x%s' "$HEX_KEY" | sha256sum | cut -c1-12)  (share this, never the key)"
