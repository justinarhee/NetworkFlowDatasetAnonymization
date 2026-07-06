#!/usr/bin/env bash
# generate_key.sh — create a local anonymization key for nfanon.
# Produces a 64-hex-digit key (valid for nfanon -K), stored 0600, git-ignored.
# NEVER commit, share, or document this key.
set -euo pipefail
KEY_FILE="${KEY_FILE:-secret/anon.key}"
mkdir -p "$(dirname "$KEY_FILE")"
if [[ -f "$KEY_FILE" ]]; then
  echo "Key already exists at $KEY_FILE (refusing to overwrite)."; exit 0
fi
# 32 random bytes -> 64 hex chars. nfanon accepts a 64-hex-digit key.
openssl rand -hex 32 > "$KEY_FILE"
chmod 600 "$KEY_FILE"
echo "Wrote new key to $KEY_FILE (perms 600)."
echo "Fingerprint: $(sha256sum "$KEY_FILE" | cut -c1-12)  (share this, never the key)"
