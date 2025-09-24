# Phase 3 — Virtualization and PageCache

## Status (branch: cancellation-and-fire-and-forget-2)
Summary: Major Phase 3 components are already implemented in this branch: virtualization in the hex viewer, a page cache implementation, and supporting scripts and CI/tracking bootstrap. Several items remain incomplete or need verification and tests (cancellation semantics, LRU eviction, MMF cross-platform fallback, and integration test coverage).

Current overall status: Partially implemented; proceed with verification, tests, and polish.

## Goals
- Provide a robust IVirtualFileReader abstraction and Page DTO.
- Provide MemoryMappedFile and FileStream readers and an IVirtualFileReaderFactory (fallback).
- Provide PageCache with dedupe, configurable throttle, and LRU eviction.
- Integrate HexViewerViewModel with the PageCache / IVirtualFileReader and enable placeholder rows while pages load.
- Add unit and integration tests for dedupe, cancellation, throttling, and UI virtualization.
- Add CI coverage that includes async-void guard, dotnet format, unit tests, and a scheduled integration test (synthetic file).
- Produce a QA/verification report with lab-run notes for cancellation semantics on hardware (manual).

## Tasks (task list updated to reflect branch changes)
- [x] Create IVirtualFileReader and Page DTO in S7.Core (note: verify namespace and file paths) — detected in branch: IVirtualFileReader / Page DTO present or analogous types implemented in Core/Service files.
- [x] Implement MemoryMappedFileVirtualReader in S7.Services (or equivalent) — detected in branch: MemoryMapped or MMF-backed reader code present (verify cross-platform behavior).
- [x] Implement FileStream fallback reader in S7.Services — present or partially present (fallback exists or service implements file-backed reads).
- [x] Implement PageCache in S7.Infrastructure with dedupe and throttle — detected in branch: page cache / dedupe pattern implemented and wired to Hex Viewer.
- [x] Add unit tests for basic cache behaviour (happy path) — present: tests for virtualization/page cache implemented (review test coverage).
- [ ] Add unit tests for dedupe under concurrency (two+ concurrent requests) — partially implemented; add explicit test asserting single underlying read count.
- [ ] Add unit tests for cancellation semantics (cancelling in-flight reads removes inflight state and allows retry) — partial: certain cancellation tests exist; need thorough coverage and edge-case tests.
- [ ] Add unit tests for throttle (max concurrent reads respected) — not fully present; add deterministic test using mock reader with delays.
- [x] Wire HexViewerViewModel to IVirtualFileReader + PageCache (placeholders and IProgress) — detected: virtualization and placeholders implemented; verify resource usage.
- [ ] Add precomputed hex string optimization (avoid per-byte allocations) — partially implemented or planned; confirm and add if missing.
- [x] Add scripts and CI scaffolding: collect-architecture, find_async_void, generate-candidate-moves, .github/workflows/ci.yml — present and executable.
- [x] Add AGENT and tracking scaffolding (.copilot-tracking/plans/.copilot-tracking/changes/) — present in branch.
- [ ] Add IVirtualFileReaderFactory to choose MMF vs FileStream at runtime for CI/OS compatibility — missing or partial; implement to ensure CI stability on all runners.
- [ ] LRU eviction in PageCache with configurable max pages and metrics (hit/miss counters) — partially implemented; add eviction verification tests and metrics.
- [ ] Integration test (synthetic large file) to verify smooth scrolling, placeholder behavior, search across pages — partial; add headless test harness or UI automation to assert virtualization behavior.
- [ ] Lab verification and cancellation semantics report (manual hardware runs) — required: schedule and capture logs.

## Acceptance criteria to mark Phase 3 complete
1. Unit tests for dedupe, cancellation, and throttle pass consistently in CI.
2. PageCache LRU eviction verified by tests and logged metrics present.
3. IVirtualFileReaderFactory implemented to handle MMF fallback on CI.
4. HexViewer integration shows smooth scrolling using synthetic large file in automated integration test.
5. A short QA report covering at least three lab runs (happy path, cancellation during upload/dump, connection flake) is committed.
6. .copilot-tracking/changes updated for all tasks and merged PRs referenced.

## Notes and verification steps
- Run: dotnet test to ensure all tests pass locally.
- Run the scanner scripts (scripts/collect-architecture.sh and scripts/generate-candidate-moves.sh) to get up-to-date reports after further refactors.
- Confirm that any MMF usage is protected by runtime checks when running on CI containers where MMF semantics differ.
- Ensure every long-running public method accepts CancellationToken and that cancellation flows through PageCache to the reader.
