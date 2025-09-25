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
    "ViewModels"
    "Views" 
    "Controls"
    "Behaviors"
    "Converters"
)

# Function to check if a file is UI-related
is_ui_file() {
    local file="$1"
    for pattern in "${UI_PATTERNS[@]}"; do
        if [[ "$file" == *"/$pattern/"* ]]; then
            return 0  # true - is UI file
        fi
    done
    return 1  # false - not UI file
}

# Find all C# files in non-UI directories
NON_UI_FILES=()
while IFS= read -r -d '' file; do
    if ! is_ui_file "$file"; then
        NON_UI_FILES+=("$file")
    fi
done < <(find "$SRC_DIR" -name "*.cs" -print0)

echo "Found ${#NON_UI_FILES[@]} non-UI C# files to check"

# Check for await calls without ConfigureAwait(false) in non-UI files
VIOLATIONS=()
for file in "${NON_UI_FILES[@]}"; do
    # Skip if file doesn't exist or is empty
    [[ -f "$file" ]] || continue
    
    # Find await calls that don't have ConfigureAwait
    while IFS= read -r line_info; do
        [[ -n "$line_info" ]] || continue
        
        line_num=$(echo "$line_info" | cut -d: -f1)
        line_content=$(echo "$line_info" | cut -d: -f2- | sed 's/^[[:space:]]*//')
        
        # Skip comments and lines that already have ConfigureAwait
        if [[ "$line_content" =~ ^// ]] || \
           [[ "$line_content" =~ ^/\* ]] || \
           [[ "$line_content" =~ "ConfigureAwait" ]] || \
           [[ "$line_content" =~ "awaitResponse" ]]; then
            continue
        fi
        
        # Check if this line contains an await call
        if [[ "$line_content" =~ await[[:space:]] ]]; then
            # Additional check: make sure it's not a variable name containing "await"
            if [[ "$line_content" =~ [[:space:]]await[[:space:]] ]] || [[ "$line_content" =~ ^await[[:space:]] ]]; then
                VIOLATIONS+=("$file:$line_num: $line_content")
            fi
        fi
    done < <(grep -n "await" "$file" 2>/dev/null || true)
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
    echo
    echo "Example fix:"
    echo "  Before: await SomeMethodAsync();"
    echo "  After:  await SomeMethodAsync().ConfigureAwait(false);"
    exit 1
fi

echo "=== Validation Complete ==="