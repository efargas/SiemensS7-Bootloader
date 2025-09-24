#!/usr/bin/env bash
set -euo pipefail

# create_workspace.sh
# Creates folders and instruction files for AI agents, workspace, plans, tracking, CI skeleton, and developer instructions.
# Run from repository root.

ROOT="$(pwd)"
echo "Repository root: $ROOT"

# Helper to create file with content
writefile() {
  local path="$1"
  local content="$2"
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"
  cat > "$path" <<'EOF'
'"$content"'
EOF
}

# Create directories
mkdir -p agents/workspace .copilot-tracking/plans .copilot-tracking/details .copilot-tracking/changes scripts docs .github/workflows reports src

# .gitignore additions
cat >> .gitignore <<'EOF'

# Agent ephemeral workspace and tracking artifacts
agents/workspace/
.copilot-tracking/changes/*.md
reports/*.csv
reports/*.txt
docs/REPO_LAYOUT_CURRENT.md
EOF

# agents/AGENT_INSTRUCTIONS.md
cat > agents/AGENT_INSTRUCTIONS.md <<'EOF'
# AI Coding Agent Instructions (Repository: SiemensS7-Bootloader)

Purpose
- Agents assist contributors by producing code, tests, docs, and change-tracking artifacts following the repo conventions below.
- Agents must not push directly to protected branches. All changes are prepared in branches and opened as PRs by a human.

General rules
- Always follow this repository's branching, PR, and tracking conventions.
- Only modify files under src/, docs/, scripts/, .copilot-tracking/, agents/workspace/ and reports/ unless instructed otherwise in a plan file.
- Never delete existing tests or change production code behavior without adding tests that demonstrate expected behavior.
- Every code change must include at least one unit test or an updated integration test that covers the change.
- When moving files between projects, create adapters in the old location with [Obsolete] and keep them for one release.

Branching and commits
- Create a feature branch: feature/<short>-<desc> or chore/<desc>.
- Write small commits (<200 LOC) and meaningful messages: prefix scope (e.g., core:, ui:, services:), then message.
- Add a plan reference in commit message: e.g., "core: add IVirtualFileReader (plan: .copilot-tracking/plans/phase3-virtualization.md)".

Plans / tracking changes
- Implementation progress is tracked in .copilot-tracking/plans and .copilot-tracking/changes.
- For each completed task:
  - Update plan file (change [ ] -> [x]).
  - Append an entry to the relevant .copilot-tracking/changes/YYYYMMDD-*.md file with Added/Modified/Removed entries.
- Agents must update plan files and produce suggested change-file content, but a human must review and commit the change file.

PR and merge rules (agents prepare PR bodies)
- Prepare PR description using .github/PULL_REQUEST_TEMPLATE.md.
- Include: summary, related plan path, acceptance checklist, tests added, and migration notes.
- Do not merge; open PR for human reviewers.

Code style and CI
- Use .editorconfig and follow naming rules (IVirtualFileReader, ReadOnlyMemory<byte>, Async suffix).
- Provide CI-friendly changes: include unit tests and ensure dotnet build/test passes locally.

Files created/modified by agents
- Agents work inside agents/workspace/ and produce patches or PR drafts.
- They also generate step-by-step instructions and suggested git commands in PR body.

Security and safety
- Do not create or modify any files under tools/, firmware, or any location containing sensitive payloads without explicit human approval.
- For hardware integration code, ensure tests are mocks or synthetic only; never run hardware commands in CI.

EOF

# .copilot-tracking template plan (phase3 example)
cat > .copilot-tracking/plans/phase3-virtualization.md <<'EOF'
# Phase 3 — Virtualization and PageCache

## Goals
- IVirtualFileReader interface and Page DTO
- MemoryMappedFile and FileStream readers plus factory
- PageCache with dedupe, throttle, and LRU eviction
- HexViewer wiring and integration tests
- CI tests and sample synthetic-file demo

## Tasks
- [ ] Create IVirtualFileReader and Page DTO in S7.Core
- [ ] Implement MemoryMappedFileVirtualReader in S7.Services
- [ ] Implement FileStream fallback reader in S7.Services
- [ ] Implement PageCache in S7.Infrastructure with dedupe/throttle/LRU
- [ ] Add unit tests for dedupe/cancel/throttle
- [ ] Wire HexViewerViewModel to IVirtualFileReader and placeholders
- [ ] Integration demo with synthetic file and QA report

## Acceptance
- Unit tests pass locally and in CI
- Demo app shows smooth scrolling on synthetic large file
- Cancellation and dedupe tests green

EOF

# .copilot-tracking/details template
cat > .copilot-tracking/details/phase3-task-1.md <<'EOF'
# Phase3 Task: IVirtualFileReader and Page DTO details

Goal
- Add IVirtualFileReader and Page DTO to S7.Core.

Requirements
- IVirtualFileReader:
  - Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
  - long Length { get; }
  - int PageSize { get; }
- Page DTO:
  - record Page(long PageIndex, ReadOnlyMemory<byte> Data, int Length)

Tests
- Contract tests: null params handling and cancellation propagation.

Notes
- Keep types immutable and allocation-light.

EOF

# .copilot-tracking/changes template file
today="$(date +%Y%m%d)"
cat > ".copilot-tracking/changes/${today}-workspace-bootstrap-changes.md" <<'EOF'
<!-- markdownlint-disable-file -->
# Release Changes: Workspace bootstrap

**Related Plan**: .copilot-tracking/plans/phase3-virtualization.md
**Implementation Date**: $(date --iso-8601=seconds)

## Summary
Bootstrap: agents folder, tracking scaffolding, CI skeletons, and contributor docs.

## Changes

### Added
- agents/AGENT_INSTRUCTIONS.md - instructions for AI coding agents
- .copilot-tracking/plans/phase3-virtualization.md - sample plan for Phase 3
- .copilot-tracking/details/phase3-task-1.md - task details template
- .copilot-tracking/changes/${today}-workspace-bootstrap-changes.md - this file
- .github/PULL_REQUEST_TEMPLATE.md - PR template
- .github/workflows/ci.yml - CI skeleton
- docs/CONTRIBUTING.md - contributor instructions
- reports/candidate-moves-template.csv - candidate moves template
- scripts/generate-candidate-moves.sh - helper to auto-generate candidate moves

### Modified
- .gitignore - added agents/workspace and reports ignore lines

### Removed
- (none)

EOF

# .github/PULL_REQUEST_TEMPLATE.md
mkdir -p .github
cat > .github/PULL_REQUEST_TEMPLATE.md <<'EOF'
## Summary

(Briefly explain the change)

## Related plan/file
- Plan: .copilot-tracking/plans/<phase>.md

## Acceptance checklist
- [ ] Build passes
- [ ] Unit tests added and passing
- [ ] Integration tests (if applicable)
- [ ] Updated .copilot-tracking/changes file

## Changes
- Added:
- Modified:
- Removed:

## Notes
(Any migration notes or manual QA steps)
EOF

# .github/workflows/ci.yml (basic)
mkdir -p .github/workflows
cat > .github/workflows/ci.yml <<'EOF'
name: CI

on:
  push:
    branches: [ main, develop, feature/*, chore/*, fix/* ]
  pull_request:
    branches: [ main, develop ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        dotnet-version: [8.0]
    steps:
      - uses: actions/checkout@v4
      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: \${{ matrix.dotnet-version }}
      - name: Restore
        run: dotnet restore
      - name: Build
        run: dotnet build --no-restore -c Release
      - name: Test
        run: dotnet test --no-build -c Release --verbosity normal
      - name: Async void guard
        run: |
          if [ -f ./scripts/find_async_void.sh ]; then
            bash ./scripts/find_async_void.sh
          else
            echo "No async-void guard script found"
          fi
      - name: Format check
        run: |
          dotnet tool restore || true
          dotnet format --verify-no-changes || true

EOF

# .editorconfig
cat > .editorconfig <<'EOF'
root = true

[*.{cs,vb}]
indent_style = space
indent_size = 4
charset = utf-8-bom
insert_final_newline = true

dotnet_style_qualification_for_field = false:suggestion
csharp_style_var_elsewhere = true:suggestion
csharp_style_expression_bodied_methods = false:suggestion

# naming rules can be tuned with analyzers / stylecop
EOF

# .gitattributes
cat > .gitattributes <<'EOF'
# Handle line endings
* text=auto

# Mark binary files
*.png binary
*.jpg binary
EOF

# docs/CONTRIBUTING.md
cat > docs/CONTRIBUTING.md <<'EOF'
# Contributing

Follow repository conventions:
- Branch: feature/<topic> or chore/<topic>
- PR: small, with acceptance checklist and plan reference
- Update .copilot-tracking/plans and append to .copilot-tracking/changes after each task
- Run scripts/collect-architecture.sh after major refactors and commit docs/REPO_LAYOUT_CURRENT.md

Coding conventions
- See .editorconfig
- Async methods must end with Async and accept CancellationToken for long-running operations
- Use DI for service wiring (Microsoft.Extensions.DependencyInjection)

CI
- All PRs must pass CI (build + tests)
EOF

# reports/candidate-moves-template.csv
cat > reports/candidate-moves-template.csv <<'EOF'
# candidate-moves-template.csv
# Columns: current_path,target_project,reason,move_risk,notes
src/S7_Csharp_Utility/Models/Profile.cs,S7.Core,DTO - pure model; no UI deps,Low,"Move to S7.Core; update references in UI project to S7.Core.Models"
EOF

# scripts/generate-candidate-moves.sh
cat > scripts/generate-candidate-moves.sh <<'EOF'
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
  ns=\$(echo "$line" | sed -E 's/^"([^"]+)".*$/\1/' || true)
  path=\$(echo "$line" | sed -E 's/^"[^"]+",?"?([^"]+)"?$/\1/' || true)
  if [[ "\$path" == src/S7_Csharp_Utility/* && "\$path" == *.cs ]]; then
    if rg --fixed-strings --quiet "\$path" "$UIREF" 2>/dev/null; then
      continue
    fi
    tgt="S7.Core"
    reason="pure model or domain type; no UI APIs detected"
    risk="Low"
    full="\$ROOT/\$path"
    if rg -n "SerialPort|System.IO.Ports|MemoryMappedFile|Bootloader|Modbus|Socket|TcpClient|SerialChannel" "\$full" >/dev/null 2>&1; then
      tgt="S7.Services"
      reason="I/O or protocol implementation detected; move to Services"
      risk="Medium"
    fi
    echo "\$path,\$tgt,\$reason,\$risk,auto-generated" >> "\$CAND"
  fi
done

echo "Candidate moves written to $CAND"
EOF
chmod +x scripts/generate-candidate-moves.sh

# scripts/find_async_void.sh (guard)
cat > scripts/find_async_void.sh <<'EOF'
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
EOF
chmod +x scripts/find_async_void.sh

# Make scripts/collect-architecture.sh executable if present
if [ -f scripts/collect-architecture.sh ]; then
  chmod +x scripts/collect-architecture.sh
fi

# agents/workspace README and .gitignore hint
cat > agents/workspace/README.md <<'EOF'
# Agents workspace (ephemeral)

Agents may use this folder for drafts and temporary artifacts.
This folder is gitignored. Do not persist final code here.

EOF

# Final message and summary
echo "Bootstrap created. Files and folders added:"
echo " - agents/AGENT_INSTRUCTIONS.md"
echo " - .copilot-tracking/plans/phase3-virtualization.md"
echo " - .copilot-tracking/details/phase3-task-1.md"
echo " - .copilot-tracking/changes/${today}-workspace-bootstrap-changes.md"
echo " - .github/PULL_REQUEST_TEMPLATE.md"
echo " - .github/workflows/ci.yml"
echo " - docs/CONTRIBUTING.md"
echo " - reports/candidate-moves-template.csv"
echo " - scripts/generate-candidate-moves.sh"
echo " - scripts/find_async_void.sh"
echo ""
echo "Next steps:"
echo "1. Run scripts/collect-architecture.sh to refresh docs/REPO_LAYOUT_CURRENT.md if needed."
echo "2. Run scripts/generate-candidate-moves.sh to populate reports/candidate-moves.csv"
echo "3. Review candidate moves and follow the incremental PR plan in AGENT_INSTRUCTIONS.md"
