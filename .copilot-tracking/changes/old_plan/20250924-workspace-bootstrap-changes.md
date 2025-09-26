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

