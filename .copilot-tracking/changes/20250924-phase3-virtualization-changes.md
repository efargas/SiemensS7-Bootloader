<!-- markdownlint-disable-file -->
# Release Changes: Phase3-virtualization-detection

**Related Plan**: .copilot-tracking/plans/phase3-virtualization.md
**Implementation Date**: 2025-09-24

## Summary

This changes file records the Phase 3 virtualization and supporting infrastructure items detected in branch cancellation-and-fire-and-forget-2. It summarizes implemented pieces and remaining work that must be completed to meet Phase 3 acceptance criteria.

## Changes

### Added
- src/.../HexViewer virtualization and PageCache implementation - implemented (exact paths vary; check src for page cache and hex-viewer implementations).
- scripts/generate-candidate-moves.sh - added
- scripts/find_async_void.sh - added/updated
- scripts/collect-architecture.sh - added/updated (scan outputs: docs/REPO_LAYOUT_CURRENT.md and reports/*)
- .github/workflows/ci.yml - CI skeleton added/updated
- agents/AGENT_INSTRUCTIONS.md - added
- .copilot-tracking/plans/phase3-virtualization.md - plan file (updated)
- reports/* (file-fingerprints.csv, namespace-file-map.csv, duplicates.txt, async_void.txt, ui_references.txt, candidate-moves-template.csv) - added

### Modified
- AGENTS.md / project plan files - annotate Phase 3 items as partially implemented
- HexViewerViewModel (UI) - now wired to page cache / virtualization (verify file path)
- Various service files - refactor to async and added cancellation support in memory dump flows
- README.md - contains updated build/run instructions and feature notes

### Removed
- (none detected automatically; remove duplicates only after canonicalization is agreed)

## Release Summary

**Total Files Affected**: many (see reports/file-fingerprints.csv for exact list)

### Files Created (high level)
- scripts/generate-candidate-moves.sh - auto-candidate generator
- scripts/find_async_void.sh - async-void guard
- scripts/collect-architecture.sh - architecture scanner
- .github/workflows/ci.yml - CI skeleton
- agents/AGENT_INSTRUCTIONS.md - instructions for AI agents
- reports/* - scan reports for planning and refactor

### Files Modified (high level)
- Hex viewer and page cache implementation files (UI + infrastructure/services) — specific paths visible in the branch (search for "page cache", "virtualization", "HexViewer").
- Many formatting/consistency edits applied by dotnet format; .editorconfig updated.

### Dependencies & Infrastructure
- **New Dependencies**: NModbus library referenced in .vscode or csproj (confirm). If MMF fallback requires a small shim, add appropriate package later.
- **Infrastructure Changes**: Basic CI workflow added (see .github/workflows/ci.yml).
- **Configuration Updates**: dotnet 8 target in project files; check all csproj for consistent TargetFramework.

### Deployment Notes
- Verify MemoryMappedFile usage on CI runners; add IVirtualFileReaderFactory to fallback to FileStream reader where MMF unsupported.
- Run the integration harness (synthetic file) locally to validate memory and UI behavior before merging further refactors.
