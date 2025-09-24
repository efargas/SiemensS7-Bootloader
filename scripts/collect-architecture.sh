#!/usr/bin/env bash
set -euo pipefail

# collect-architecture.sh
# Scans repository under src/ and produces:
# - docs/REPO_LAYOUT_CURRENT.md
# - reports/file-fingerprints.csv
# - reports/namespace-file-map.csv
# - reports/duplicates.txt
# - reports/async_void.txt
# - reports/ui_references.txt
# - summary printed to stdout
#
# Usage: ./scripts/collect-architecture.sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/src"
OUT_DIR="$ROOT/reports"
DOCS_DIR="$ROOT/docs"

mkdir -p "$OUT_DIR" "$DOCS_DIR"

echo "Collecting solution and project files..."
# List .sln and csproj files
echo "# Solution and Projects" > "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
echo "" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
echo "Generated on: $(date --iso-8601=seconds)" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
echo "" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"

if command -v dotnet >/dev/null 2>&1; then
  dotnet --version > "$OUT_DIR/dotnet-version.txt" || true
  echo "dotnet version: $(cat $OUT_DIR/dotnet-version.txt)" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
fi

echo "## Solutions" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
find "$ROOT" -maxdepth 2 -name "*.sln" -print >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md" || true
echo "" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"

echo "## Projects" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
find "$SRC_DIR" -type f -name "*.csproj" | sed "s|$ROOT/||" | sort >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md" || true
echo "" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"

# Create fingerprint CSV (sha1, path, size)
echo "sha1,sum_bytes,relpath" > "$OUT_DIR/file-fingerprints.csv"
git ls-files "$SRC_DIR" | while read -r f; do
  full="$ROOT/$f"
  if [ -f "$full" ]; then
    sha=$(sha1sum "$full" | awk '{print $1}')
    size=$(stat -c%s "$full" 2>/dev/null || stat -f%z "$full" 2>/dev/null || echo 0)
    echo "${sha},${size},${f}" >> "$OUT_DIR/file-fingerprints.csv"
  fi
done

# duplicates
echo "Duplicate file fingerprints (sha1) (reports/duplicates.txt):"
awk -F, 'NR>1{a[$1]++; if(a[$1]==2) print $1}' "$OUT_DIR/file-fingerprints.csv" > "$OUT_DIR/duplicate-sha1.txt" || true
if [ -s "$OUT_DIR/duplicate-sha1.txt" ]; then
  > "$OUT_DIR/duplicates.txt"
  while read -r sha; do
    echo "=== Duplicate group: $sha" >> "$OUT_DIR/duplicates.txt"
    awk -F, -v s="$sha" 'NR>1 && $1==s{print $3}' "$OUT_DIR/file-fingerprints.csv" >> "$OUT_DIR/duplicates.txt"
    echo "" >> "$OUT_DIR/duplicates.txt"
  done < "$OUT_DIR/duplicate-sha1.txt"
else
  echo "No exact duplicates found." > "$OUT_DIR/duplicates.txt"
fi
cat "$OUT_DIR/duplicates.txt"

# Build namespace -> file map (approx): look for "namespace" lines
echo "namespace,relpath" > "$OUT_DIR/namespace-file-map.csv"
git ls-files "$SRC_DIR" | while read -r f; do
  full="$ROOT/$f"
  if [ -f "$full" ]; then
    # extract the first namespace declaration (if any)
    ns=$(rg --no-line-number -m 1 '^namespace\s+' "$full" 2>/dev/null || true)
    if [ -n "$ns" ]; then
      ns_clean=$(echo "$ns" | sed -E 's/namespace[[:space:]]+//; s/[[:space:]]*$//')
      echo "\"$ns_clean\",\"$f\"" >> "$OUT_DIR/namespace-file-map.csv"
    fi
  fi
done

# Find async void occurrences
echo "Scanning for async void occurrences..."
rg --hidden --no-ignore --line-number --glob '!**/bin/**' --glob '!**/obj/**' "async void" "$SRC_DIR" -S > "$OUT_DIR/async_void.txt" || true
if [ ! -s "$OUT_DIR/async_void.txt" ]; then
  echo "No 'async void' occurrences found." > "$OUT_DIR/async_void.txt"
fi
echo "-> async_void report saved to $OUT_DIR/async_void.txt"

# Find UI references (Avalonia, Dispatcher, Application.Current, Window, Control)
echo "Scanning for UI references (Avalonia, Dispatcher, Application.Current)..."
rg --hidden --no-ignore --line-number --glob '!**/bin/**' --glob '!**/obj/**' "Avalonia|Dispatcher|Application.Current|Window|Control" "$SRC_DIR" -S > "$OUT_DIR/ui_references.txt" || true
if [ ! -s "$OUT_DIR/ui_references.txt" ]; then
  echo "No UI reference occurrences found." > "$OUT_DIR/ui_references.txt"
fi
echo "-> UI references report saved to $OUT_DIR/ui_references.txt"

# Create a projects file listing with file counts
echo "## Project file counts" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
for proj in $(find "$SRC_DIR" -maxdepth 2 -name "*.csproj"); do
  relproj=$(echo "$proj" | sed "s|$ROOT/||")
  count=$(git ls-files | rg "^src/$(basename $(dirname "$proj"))" -n | wc -l || true)
  echo "- $relproj (approx files: $count)" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
done

# Dump top-level folders and file counts
echo "" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
echo "## Top-level folders under src/" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
for d in $(find "$SRC_DIR" -mindepth 1 -maxdepth 1 -type d | sort); do
  rel=$(echo "$d" | sed "s|$ROOT/||")
  files=$(git ls-files "$rel" | wc -l)
  echo "- $rel (files: $files)" >> "$DOCS_DIR/REPO_LAYOUT_CURRENT.md"
done

# Create a brief summary file
SUMMARY="$OUT_DIR/summary.txt"
echo "Architecture scan summary - $(date --iso-8601=seconds)" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Projects (csproj):" >> "$SUMMARY"
find "$SRC_DIR" -type f -name "*.csproj" -print >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Reports generated in $OUT_DIR and $DOCS_DIR/REPO_LAYOUT_CURRENT.md" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Duplicates: see $OUT_DIR/duplicates.txt" >> "$SUMMARY"
echo "Async void occurrences: see $OUT_DIR/async_void.txt" >> "$SUMMARY"
echo "UI references: see $OUT_DIR/ui_references.txt" >> "$SUMMARY"

cat "$SUMMARY"
echo ""
echo "Done. Reports: "
ls -l "$OUT_DIR" || true
echo "Open $DOCS_DIR/REPO_LAYOUT_CURRENT.md and the files in $OUT_DIR for details."
