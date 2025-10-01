# Phase 3 — Virtualization and PageCache

## Status (branch: fix/page-cache-lru-logic)
Summary: The branch implements the core PageCache and hex-viewer virtualization. A race in the LRU eviction logic was fixed. Remaining work: thorough unit tests for eviction under concurrency, IVirtualFileReaderFactory fallback, LRU metrics and optional inflight cleanup, integration (synthetic) test harness, and lab verification for cancellation semantics on hardware.

Current overall status: Mostly implemented; verification and targeted tests required.

## Goals
- IVirtualFileReader abstraction and Page DTO (implemented).
- MMF and FileStream readers with a runtime factory (MMF present; factory may be missing).
- PageCache with dedupe, semaphore-based throttling, robust LRU eviction (implemented and fixed on this branch).
- HexViewerViewModel integration with placeholders and IProgress (implemented).
- Unit tests for dedupe, cancellation, throttle, eviction (partial; eviction test failing was addressed; expand coverage).
- Integration test using synthetic large file to confirm UI virtualization and search across pages (pending).
- QA lab runs to validate cancellation semantics with hardware (pending).

## Tasks (updated)
- [x] Create IVirtualFileReader and Page DTO in S7.Core.
- [x] Implement MemoryMappedFileVirtualReader in S7.Services (verify cross-platform behavior).
- [x] Implement FileStream fallback reader (present or partial).
- [x] Implement PageCache with dedupe, throttle and LRU eviction — implemented and LRURace fixed in branch fix/page-cache-lru-logic.
- [x] Add unit tests for basic cache behaviour (happy path).
- [x] Fix race causing eviction test failure by:
  - using Lazy<Task<Page>> for inflight dedupe,
  - evicting inside lock with a while loop,
  - removing inflight only on failure — implemented in branch.
- [ ] Add explicit unit test for concurrent eviction scenario (multiple concurrent inserts exceeding capacity) and assert final LRU correctness.
- [ ] Add unit test to assert eviction removes least-recently-used keys deterministically.
- [ ] Add deterministic throttle test asserting max concurrent reads (if not already present).
- [ ] Add IVirtualFileReaderFactory to select MMF or FileStream at runtime for CI compatibility.
- [ ] Add eviction and cache-metrics (hit/miss/eviction counters) and expose for tests.
- [ ] Add integration test (headless or UI automation) that opens synthetic large file, scrolls, and asserts placeholder behavior and search across pages.
- [ ] Add lab QA report: 3 runs (happy-path, cancellation during upload/dump, network flake) and attach logs to .copilot-tracking/changes.

## Acceptance criteria
- All unit tests (dedupe, cancellation, throttle, eviction) pass reliably in CI.
- PageCache LRU eviction behavior verified by unit tests. Final cache size <= configured cacheSize.
- IVirtualFileReaderFactory exists to fallback to FileStream in CI environments.
- Integration test demonstrates smooth scrolling and search across pages.
- QA report committed with logs for lab runs.

## Notes
- Ensure Page is immutable (ReadOnlyMemory<byte>) or treated as immutably when shared.
- Consider small cleanup to remove long-lived successful inflight entries after some TTL if memory is a concern.