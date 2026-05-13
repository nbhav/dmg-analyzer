#!/bin/bash
# analyze.sh — host-side entrypoint
# Usage: ./analyze.sh <path-to.dmg>
set -euo pipefail

DMG_PATH="${1:?Usage: ./analyze.sh <path-to.dmg>}"

if [[ -z "${DMG_PATH}" || ! -f "${DMG_PATH}" ]]; then
  echo "ERROR: File not found: ${DMG_PATH}" >&2
  exit 1
fi

DMG_NAME=$(basename "${DMG_PATH}" .dmg)
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$REPO_DIR/output/${DMG_NAME}"

mkdir -p "${OUTPUT_DIR}"

echo "[*] Analyzing: ${DMG_NAME}"
echo "[*] Output:    ${OUTPUT_DIR}"

# DMG is piped into the container via stdin — no input bind mount at all.
# Output bind mount is the only host filesystem exposure.
# Might be overly paranoid but wanted to avoid dmg potentially escaping to host via bind mount
# during analysis. 

cat "${DMG_PATH}" | container run \
  --rm \
  --interactive \
  --network none \
  --memory=4g \
  --cpus=2 \
  --mount type=bind,source="$OUTPUT_DIR",target=/output \
  dmg-analyzer:latest \
  "$DMG_NAME"

echo "[*] Done. Reports in: $OUTPUT_DIR"
