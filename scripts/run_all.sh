#!/bin/bash
# scripts/run_all.sh — runs inside the container
# Receives DMG via stdin, name as $1
set -euo pipefail

DMG_NAME="${1:?no dmg name provided}"
EXTRACT="/tmp/extracted"
OUTPUT="/output"
DMG_PATH="/tmp/target.dmg"

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

# ── Run analysis modules ──────────────────────────────────────────────────────
run_module() {
  local label="$1"
  local script="$2"
  local outfile="$3"
  echo "[*] Running: $label"
  python3 "src/$script" "$EXTRACT" "$outfile" 2>/dev/null \
    || echo '{"error":"module_failed","module":"'"$label"'"}' > "$outfile"
}

run_module "bundle_structure" "bundle_structure.py" "$OUTPUT/00_bundle_structure.json"
run_module "binary_info"      "binary_info.py"      "$OUTPUT/01_binary_info.json"
run_module "code_signing"     "code_signing.py"     "$OUTPUT/02_code_signing.json"
run_module "plist_audit"      "plist_audit.py"      "$OUTPUT/03_plist_audit.json"
run_module "secrets"          "secrets.py"          "$OUTPUT/04_secrets.json"
run_module "endpoints"        "endpoints.py"        "$OUTPUT/05_endpoints.json"
run_module "frameworks"       "frameworks.py"       "$OUTPUT/06_frameworks.json"

# Raw strings dump from all executables
echo "[*] Extracting strings..."
find "$EXTRACT" -type f \( -perm /111 -o -name "*.dylib" \) \
  | xargs -I{} strings -a {} 2>/dev/null \
  | sort -u \
  > "$OUTPUT/07_strings.txt"

# Summary rollup
echo "[*] Building summary..."
python3 src/summarize.py "$DMG_NAME" "$OUTPUT"

echo "[*] Analysis complete"
