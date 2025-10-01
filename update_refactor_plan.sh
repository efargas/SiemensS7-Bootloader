#!/usr/bin/env bash
set -euo pipefail
BRANCH="refactor/plan-update"
echo "Creating branch $BRANCH"
git checkout -b "$BRANCH"

mkdir -p docs agents .copilot-tracking scripts

echo "Writing docs/DEV_PLAN.md"
cat > docs/DEV_PLAN.md <<'MD'
# Refactor Plan (summary)

This document captures the phased refactor plan to split UI, core protocol, adapters, and tools.

Phases:
- Phase 0: Prep (editorconfig, gitattributes, copilot-tracking details)
- Phase 1: Skeleton (create S7_Lib, S7_Adapters, S7_Tools, tests)
- Phase 2: Extract DTOs and parsing (move with tests)
- Phase 3: IO adapters and DI wiring
- Phase 4: CI polish and cleanup
- Phase 5: Documentation and release

Acceptance criteria:
- All new projects build: dotnet build <solution> succeeds
- Unit tests: dotnet test passes
- CI: normalize-encoding runs; dotnet format auto-fix runs; build and test pass
MD

echo "Writing agents/agent_instructions.md"
cat > agents/agent_instructions.md <<'MD'
# Coding Agent Instructions (atomic tasks)

1. Create projects (Phase 1 skeleton)
   - dotnet new classlib -n S7_Lib -o src/S7_Lib --framework net8.0
   - dotnet new classlib -n S7_Adapters -o src/S7_Adapters --framework net8.0
   - dotnet new console -n S7_Tools -o src/S7_Tools --framework net8.0
   - dotnet new xunit -n S7_Lib.Tests -o tests/S7_Lib.Tests --framework net8.0
   - Add projects to solution and ensure dotnet build succeeds.

2. Incremental extraction (Phase 2)
   - For each protocol file in src/S7_Csharp_Utility:
     - Move file to S7_Lib/Protocol
     - Add unit test in tests/S7_Lib.Tests
     - Update UI project references to S7_Lib types
     - Ensure 'dotnet test' passes

3. IO adapters (Phase 3)
   - Create ISerialAdapter in S7_Lib/IO
   - Implement SerialAdapter/TcpAdapter in S7_Adapters
   - Wire DI in S7_Csharp_Utility

4. CI and scripts
   - Ensure scripts/normalize-encoding.sh exists and is executable
   - Make sure CI workflow references scripts and performs format+rebase push

Branch & PR rules:
- Create branch per task: refactor/<short-task>
- PR title: refactor(<area>): short description
- PR must include tests for moved code and pass CI
MD

echo "Writing .copilot-tracking/details"
cat > .copilot-tracking/details <<'YAML'
owner: ""
phase: "phase-0"
started_at: ""
tasks:
  - name: add-editorconfig
    done: false
  - name: scaffold-projects
    done: false
  - name: create-scripts
    done: false
notes: "Update this file when starting a new phase or assigning an agent"
YAML

echo "Adding scripts/normalize-encoding.sh (iconv-only safe)"
cat > scripts/normalize-encoding.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
globs=( '*.cs' '*.xaml' '*.axaml' '*.config' '*.csproj' '*.sln' '*.md' '*.txt' )
tmpfile=$(mktemp)
failed=$(mktemp)
changed=false
if ! command -v iconv >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends libc-bin
  fi
fi
# iterate tracked files safely
git ls-files -- "${globs[@]}" 2>/dev/null | sort -u | while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || continue
  size=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [ "$size" -le $((1024*1024)) ] || { echo "Skipping large file: $f"; continue; }
  enc=$(file -i "$f" 2>/dev/null | awk -F'charset=' '{print $2}' | tr -d ' \n' || true)
  enc=${enc:-utf-8}
  enc=$(echo "$enc" | tr '[:upper:]' '[:lower:]')
  if [[ "$enc" == "utf-8" || "$enc" == "us-ascii" ]]; then
    continue
  fi
  echo "Attempting conversion: $f from $enc -> UTF-8"
  if iconv -f "$enc" -t UTF-8 "$f" -o "$tmpfile" 2>/dev/null; then
    if ! cmp -s "$f" "$tmpfile"; then
      mv "$tmpfile" "$f"
      changed=true
      echo "Converted: $f"
    fi
  else
    echo "iconv failed for $f (detected: $enc)" >> "$failed"
  fi
done
rm -f "$tmpfile"
if [ -s "$failed" ]; then
  echo "Files iconv could not convert:"
  sed -n '1,200p' "$failed" || true
fi
rm -f "$failed"
if [ "$changed" = true ] ; then
  echo "Files converted; commit in CI step if desired."
fi
SH
chmod +x scripts/normalize-encoding.sh

echo "Stage files"
git add docs/DEV_PLAN.md agents/agent_instructions.md .copilot-tracking/details scripts/normalize-encoding.sh

git commit -m "chore(refactor): update plan, agent instructions and copilot-tracking details" || echo "Nothing to commit"
echo "Branch prepared: $BRANCH (changes committed locally). Review and push when ready."
