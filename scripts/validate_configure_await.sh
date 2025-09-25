#!/bin/bash

# Script to validate that all non-UI await calls have ConfigureAwait(false)
# This helps ensure proper async/await patterns in non-UI code

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/src"

echo "=== ConfigureAwait(false) Validation ==="
echo "Checking for missing ConfigureAwait(false) in non-UI code..."

# Define patterns for UI-related directories that should NOT use ConfigureAwait(false)
UI_PATTERNS=(
    "*/ViewModels/*"
    "*/Views/*" 
    "*/Controls/*"
    "*/Behaviors/*"
    "*/Converters/*"
)

# Find all C# files in non-UI directories
NON_UI_FILES=()
while IFS= read -r -d '' file; do
    is_ui_file=false
    for pattern in "${UI_PATTERNS[@]}"; do
        if [[ "$file" == $pattern ]]; then
            is_ui_file=true
            break
        fi
    done
    
    if [[ "$is_ui_file" == false ]]; then
        NON_UI_FILES+=("$file")
    fi
done < <(find "$SRC_DIR" -name "*.cs" -print0)

# Check for await calls without ConfigureAwait(false) in non-UI files
VIOLATIONS=()
for file in "${NON_UI_FILES[@]}"; do
    # Look for await calls that don't have ConfigureAwait
    while IFS= read -r line; do
        line_num=$(echo "$line" | cut -d: -f1)
        line_content=$(echo "$line" | cut -d: -f2-)
        
        # Skip lines that are comments or contain "awaitResponse" or other non-await patterns
        if [[ "$line_content" =~ ^[[:space:]]*// ]] || \
           [[ "$line_content" =~ "awaitResponse" ]] || \
           [[ "$line_content" =~ "ConfigureAwait" ]]; then
            continue
        fi
        
        # Check if this is actually an await call
        if [[ "$line_content" =~ await[[:space:]] ]]; then
            VIOLATIONS+=("$file:$line_num: $line_content")
        fi
    done < <(grep -n "await.*[^)];" "$file" 2>/dev/null || true)
done

# Report results
if [[ ${#VIOLATIONS[@]} -eq 0 ]]; then
    echo "✅ All non-UI await calls properly use ConfigureAwait(false)"
    echo "Checked ${#NON_UI_FILES[@]} non-UI C# files"
else
    echo "❌ Found ${#VIOLATIONS[@]} await calls missing ConfigureAwait(false):"
    echo
    for violation in "${VIOLATIONS[@]}"; do
        echo "  $violation"
    done
    echo
    echo "Please add .ConfigureAwait(false) to these await calls in non-UI code"
    exit 1
fi

echo "=== Validation Complete ==="