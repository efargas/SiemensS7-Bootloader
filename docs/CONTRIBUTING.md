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
