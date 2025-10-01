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

