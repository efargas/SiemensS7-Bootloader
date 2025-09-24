### Purpose
Describe what the program is, why it exists, and the long-term intent.

- Purpose: a cross-platform .NET utility (Avalonia UI) to interact with Siemens S7 bootloaders and to inspect, edit, compare, and upload binary/hex images to PLC devices. It must be responsive with large files, robust against unreliable I/O (serial/USB/ethernet), and easy to test and extend.
- Long-term intent: clean MVVM architecture with testable services for protocol and file I/O, a virtualized, low-memory hex viewer, reliable bootloader operations with progress/cancellation/retries, and a maintainable CI-backed codebase.

---

### Current status and high-level review
Where the repo stands today and core findings from the recent refactor work.

- Good improvements already made: async naming, FireAndForget helper, ViewModel CTS plumbing, initial virtualization work for the hex viewer, and domain separation attempts.
- Remaining gaps:
  - Command ergonomics and cancellation coordination need stabilization.
  - Lower-level I/O/services are not yet consistently cancellation-aware or async-first.
  - Some fire-and-forget and async void patterns still exist in places.
  - Page-loading/deduplication and MMF-backed reader are not yet implemented or are partial.
  - Tests and CI guards for these concurrency issues are incomplete.
- Risk summary: without consistent token propagation, ConfigureAwait usage, and service-level async I/O, cancellation will be ineffective and background exceptions may be lost or mishandled.

---

### Target architecture and project structure
How the codebase should look when the refactor is complete.

- High-level layers
  1. UI (Avalonia Views) — XAML and minimal code-behind only for platform specifics.
  2. Presentation (ViewModels) — thin orchestration layer, exposes commands and observable state, owns CancellationTokenSource lifecycle and UI progress marshalling.
  3. Services (domain & I/O) — protocol clients, serial/ethernet transport, file providers, hashing/diff utilities; all async-first and cancellation-aware.
  4. Infrastructure — logging/notification, concurrency utilities (TaskExtensions), caching primitives (LRU/page cache), DI wiring.
  5. Core domain (pure logic) — hex formatting, diff/search algorithms, checksum computation; pure functions covered by unit tests.
- Key interfaces (examples)
  - ITransportClient (ConnectAsync, ReadAsync, WriteAsync with CancellationToken)
  - IVirtualFileReader (ReadPageAsync(pageIndex, pageSize, ct) -> Page)
  - IHexSearchService (SearchAsync(pattern, ct) -> matches as offsets)
  - INotificationService (LogInfo/Warning/Error thread-safe)
- Hex Viewer design
  - Data virtualization + UI virtualization: an items provider that exposes row count, placeholder rows, and asynchronously populates pages.
  - MMF-backed reader with page cache: ConcurrentDictionary<long, Task<Page>> dedupe + SemaphoreSlim throttle + LRU eviction.
  - Search operates on pages with overlap window to avoid misses across page boundaries.
- Concurrency model
  - VMs manage CTS and call async service methods with ct.
  - Services use async I/O (ReadAsync + ct) and ConfigureAwait(false).
  - IProgress<T> or Dispatcher used only in VMs to marshal UI updates.

---

### All points to address (detailed checklist)
A comprehensive list of code/behavioral items to fix or implement.

- Async/Cancellation
  - Convert all non-framework async void to Task.
  - Ensure all long-running public methods accept CancellationToken and respect it.
  - Use ConfigureAwait(false) in non-UI library code.
- Commands & ViewModels
  - Stabilize AsyncRelayCommand ergonomics: prefer VM StartX wrappers that manage CTS; provide adapters for simple fire-and-forget commands.
  - Keep ICommand.Execute as thin async void only, calling Task-returning methods.
  - Ensure CTS lifecycle: cancel previous, dispose, null-out, and dispose on VM cleanup.
- Services & I/O
  - Make all I/O services async-first and accept CancellationToken.
  - Replace blocking reads with ReadAsync and MMF async reads.
  - Implement IVirtualFileReader with MemoryMappedFile-backed implementation.
- Caching & Concurrency
  - Page-load deduplication: ConcurrentDictionary<long, Task<Page>> to avoid duplicate loads.
  - Throttle concurrent I/O with SemaphoreSlim (configurable).
  - Use ReadOnlyMemory<byte> or immutable Page objects to avoid sharing mutable buffers.
- Hex viewer & UI
  - Ensure UI virtualization in XAML; implement placeholder rows on cache misses.
  - Precompute hex string table for bytes 0..255 to avoid repeated allocations.
  - Search: page-overlap scanning; return absolute offsets for jump-to-result.
- Exception handling & logging
  - Use TaskExtensions.FireAndForget everywhere and route exceptions to INotificationService.LogError.
  - Make NotificationService safe for background threads (thread-safe queue or lock).
  - Centralize unobserved task exception logging.
- Tests & CI
  - Unit tests for pure functions (hex formatting, checksum).
  - Tests for page cache dedupe, cancellation, and search across pages.
  - CI job to detect stray "async void" and run dotnet format.
- Code style & maintainability
  - Async naming suffixes.
  - Consolidate duplicated utilities into single modules.
  - Add EditorConfig / dotnet format, treat key warnings as errors in CI.

---

### Gradual implementation plan (phased, incremental PRs)
Concrete phases with goals, deliverables, acceptance criteria and estimated effort.

Phase 0 — Stabilize current branch (1–3 days)
- Tasks
  - Repo-wide search/fix for "async void" and Task.Run used for I/O.
  - Ensure FireAndForget usages pass a logging handler and add a unit test for FireAndForget.
  - Add ViewModelBase Dispose/DisposeAsync to cleanup CTS and resources.
- Acceptance
  - No non-framework async void left.
  - FireAndForget test passes.
  - CTS disposed when VMs are disposed.

Phase 1 — Command ergonomics and CTS patterns (PR 1.5-A, 1–2 days)
- Tasks
  - Add AsyncRelayCommand overloads/adapters or add a small RelayCommand wrapper so ViewModels call StartX().
  - Update command wiring to use VM StartX patterns when cancellation is needed.
  - Small docs/usage example in README.
- Acceptance
  - Commands call VM StartX and CTS cancellation works from UI Cancel buttons.

Phase 2 — Service cancellation audit (PR 1.5-C, 2–4 days)
- Tasks
  - Update bootloader/serial/file services to accept CancellationToken.
  - Replace blocking reads with ReadAsync and pass ct.
  - Add ConfigureAwait(false) in non-UI code paths.
  - Add unit test that cancels a service read and verifies resources freed.
- Acceptance
  - At least file read and bootloader read support cancellation and pass cancellation tests.

Phase 3 — IVirtualFileReader + page cache (PR #2, 3–5 days)
- Tasks
  - Design IVirtualFileReader and implement MemoryMappedFile reader returning Page objects.
  - Implement dedupe (ConcurrentDictionary<long, Task<Page>>) and throttling (SemaphoreSlim).
  - Add LRU eviction policy for page cache.
  - Add unit tests for dedupe, throttling, cancellation.
- Acceptance
  - Concurrent page requests dedupe to one read; cancellation during load cancels page load; tests pass.

Phase 4 — Hex viewer integration & UI polish (PR #3, 2–4 days)
- Tasks
  - Wire HexViewerViewModel to IVirtualFileReader; show placeholder rows for missing pages.
  - Implement IProgress<PageLoaded> updates and batch UI updates to throttle UI churn.
  - Implement precomputed byte->hex string cache and optimize row rendering.
  - Add search implementing page-overlap scanning.
- Acceptance
  - Scrolling large files is smooth; placeholders show while loading; search finds matches across page boundaries; UI responsiveness validated with large synthetic files.

Phase 5 — Logging, tests, CI, and polish (PR #4, 1–2 days)
- Tasks
  - Centralize logging and NotificationService improvements.
  - Add CI guard for "async void" and run dotnet format.
  - Finish unit/integration tests and add a large-file stress integration test.
- Acceptance
  - CI green, formatting enforced, tests passing.

Phase 6 — Optional micro-optimizations & feature parity (PR #5, ongoing)
- Tasks
  - Precompute/compact hex rendering caches; performance tune memory usage; add benchmarks.
  - Improve UX: diff views, better error messages, retry/backoff policies for transient transport errors.
- Acceptance
  - Benchmarks show improved memory and CPU usage on large files.

---

### Acceptance criteria before merging each major PR
- All async public methods return Task/Task<T> (no stray async void).
- CancellationToken flows from UI down to I/O and services respond promptly to cancellation.
- Fire-and-forget tasks log exceptions via NotificationService; no silent failures.
- Unit tests for core behaviors (cancellation, dedupe, search) are present and pass.
- CI builds, format, and tests pass.

---

### Roles and responsibilities (concise)
- Maintainer: merges PRs, assigns reviewers, oversees CI.
- Async/Cancellation engineer: Phases 0–2 (stabilize commands, services).
- I/O/Virtualization engineer: Phases 3–4 (MMF, page cache, hex viewer integration).
- QA/Test owner: write/verify unit + integration tests, run stress tests.
- DevOps: add CI guards, formatting checks.