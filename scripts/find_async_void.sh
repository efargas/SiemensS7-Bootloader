#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/src"
OUT="$ROOT/reports"
mkdir -p "$OUT"
rg --no-line-number -n --hidden --glob '!**/bin/**' --glob '!**/obj/**' "async void" "$SRC_DIR" -S > "$OUT/async_void.txt" || true
if [ -s "$OUT/async_void.txt" ]; then
  echo "ERROR: Found async void occurrences:"
  sed -n '1,200p' "$OUT/async_void.txt"
  exit 2
else
  echo "No async void occurrences found."
fi
