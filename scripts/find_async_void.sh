#!/usr/bin/env bash
set -euo pipefail

# Whitelist: files or patterns where async void is allowed (semicolon-separated)
# Update or extend this list as needed.
WHITELIST="Commands/AsyncRelayCommand.cs;.*\\\\/Commands\\\\/AsyncRelayCommand.cs"

# Search pattern (matches async void as a whole word)
PATTERN='async\s+void\b'

# Exclude common comment line starts (//, ///, *) using PCRE negative lookahead
# This pattern matches lines that contain async void but do NOT start with optional whitespace followed by //, /// or *.
PCRE_PATTERN='^(?!\s*(///|//|\*)).*'${PATTERN}

# Use rg if available (PCRE2 with -P), otherwise use grep as fallback
if command -v rg >/dev/null 2>&1; then
  # Search repository ignoring bin/ and obj/ directories
  results=$(rg --hidden --no-ignore-vcs --glob '!**/bin/**' --glob '!**/obj/**' --line-number --color=never -P "${PCRE_PATTERN}" || true)
else
  # Fallback: grep may not support lookahead; filter comments out with awk
  raw=$(grep -RIn --exclude-dir=bin --exclude-dir=obj --line-number -E "${PATTERN}" . || true)
  if [ -z "$raw" ]; then
    results=""
  else
    # Remove lines that start with optional whitespace then //, /// or *
    results=$(printf "%s\n" "$raw" | awk '!/^[[:space:]]*(\/\/|\/{3}|\*)/')
  fi
fi

# If nothing found, report success
if [ -z "$results" ]; then
  echo "No async void occurrences found"
  exit 0
fi

# Filter out whitelisted files/patterns
filtered=""
while IFS= read -r line; do
  filepath=$(printf "%s" "$line" | cut -d: -f1)
  skip=false
  IFS=';' read -ra pats <<< "$WHITELIST"
  for p in "${pats[@]}"; do
    if [[ "$filepath" =~ $p ]]; then
      skip=true
      break
    fi
  done
  if ! $skip; then
    filtered+="$line"$'\n'
  fi
done <<< "$results"

if [ -z "$filtered" ]; then
  echo "Only whitelisted async void occurrences found; continuing."
  exit 0
fi

# Print findings and fail
echo "ERROR: Found disallowed async void occurrences:"
printf "%s\n" "$filtered"
exit 2
