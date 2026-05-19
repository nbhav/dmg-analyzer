#!/bin/bash
# scripts/run_all.sh — runs inside the container
# Receives DMG via stdin, name as $1
set -euo pipefail

DMG_NAME="${1:?no dmg name provided}"
EXTRACT="/tmp/extracted"
OUTPUT="/output"
DMG_PATH="/tmp/target.dmg"

export PYTHONPATH="/work/src"

mkdir -p "$EXTRACT"

# Read DMG from stdin into ephemeral container storage
echo "[*] Reading DMG from stdin..."
cat /dev/stdin > "$DMG_PATH"

echo "[*] DMG size: $(du -sh "$DMG_PATH" | cut -f1)"

# ── Safety checks before extraction ──────────────────────────────────────────

# Decompression bomb check
TOTAL_SIZE=$(7z l "$DMG_PATH" 2>/dev/null | awk '/Total/{s=$3} END{print s+0}')
MAX_BYTES=$((3 * 1024 * 1024 * 1024))
if [ "${TOTAL_SIZE:-0}" -gt "$MAX_BYTES" ]; then
  echo '{"error":"decompression_bomb","total_bytes":'"$TOTAL_SIZE"'}' > "$OUTPUT/error.json"
  echo "[!] Decompression bomb detected — aborting" >&2
  exit 1
fi

# Path traversal check
if 7z l "$DMG_PATH" 2>/dev/null | grep -qP '\.\.[/\\]'; then
  echo '{"error":"path_traversal_detected"}' > "$OUTPUT/error.json"
  echo "[!] Path traversal in archive — aborting" >&2
  exit 1
fi

# ── Extract ───────────────────────────────────────────────────────────────────
echo "[*] Extracting..."
7z x "$DMG_PATH" -o"$EXTRACT" -y 2>/dev/null || {
  echo '{"error":"extraction_failed"}' > "$OUTPUT/error.json"
  exit 1
}

# ── Symlink audit — neutralize escapes before any script touches the tree ─────
echo "[*] Auditing symlinks..."
SYMLINK_LOG="$OUTPUT/symlinks_removed.txt"
find "$EXTRACT" -type l | while read -r link; do
  real=$(realpath --no-symlinks "$link" 2>/dev/null || echo "UNRESOLVABLE")
  if [[ "$real" != "$EXTRACT"* ]]; then
    echo "REMOVED: $link -> $real" | tee -a "$SYMLINK_LOG"
    rm -f "$link"
  fi
done

# ── Run analysis pipeline ─────────────────────────────────────────────────────
echo "[*] Running analysis pipeline..."
python3 /work/src/main.py \
  --dmg-name "$DMG_NAME" \
  --extract-dir "$EXTRACT" \
  --output-dir "$OUTPUT" \
  2>>"$OUTPUT/analyzer.log"

echo "[*] Analysis complete — logs: $OUTPUT/analyzer.log"
