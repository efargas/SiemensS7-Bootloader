#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/reports"
NSMAP="$OUT/namespace-file-map.csv"
UIREF="$OUT/ui_references.txt"
CAND="$OUT/candidate-moves.csv"

mkdir -p "$OUT"
echo "#candidate-moves" > "$CAND"
echo "#current_path,target_project,reason,move_risk,notes" >> "$CAND"

if [ ! -f "$NSMAP" ]; then
  echo "Namespace map not found at $NSMAP. Run scripts/collect-architecture.sh first."
  exit 1
fi

tail -n +2 "$NSMAP" | while IFS= read -r line; do
  ns=$(echo "$line" | cut -d, -f1 | tr -d '"')
  path=$(echo "$line" | cut -d, -f2 | tr -d '"')
  
  if [[ "$path" == "src/S7_Csharp_Utility/"* && "$path" == *".cs" ]]; then
    # If the path is listed in the UI references file, skip it
    if rg --fixed-strings --quiet "$path" "$UIREF" 2>/dev/null; then
      continue
    fi
    
    tgt="S7.Core"
    reason="pure model or domain type; no UI APIs detected"
    risk="Low"
    full="$ROOT/$path"
    
    # Check for I/O or protocol-related keywords
    if rg -q "SerialPort|System.IO.Ports|MemoryMappedFile|Bootloader|Modbus|Socket|TcpClient|SerialChannel" "$full" 2>/dev/null; then
      tgt="S7.Services"
      reason="I/O or protocol implementation detected; move to Services"
      risk="Medium"
    fi
    
    echo "$path,$tgt,$reason,$risk,auto-generated" >> "$CAND"
  fi
done

echo "Candidate moves written to $CAND"