# AGENTS.md

Purpose: a cross-platform .NET utility (Avalonia UI) to interact with Siemens S7 bootloaders and to inspect, edit, compare, and upload binary/hex images to PLC devices. It must be responsive with large files, robust against unreliable I/O (serial/USB/ethernet), and easy to test and extend.

Long-term intent: clean MVVM architecture with testable services for protocol and file I/O, a virtualized, low-memory hex viewer, reliable bootloader operations with progress/cancellation/retries, and a maintainable CI-backed codebase.

---

## Repository solution and folder architecture (current)
This outlines the actual solution/projects seen in the branch feature/cancellation-and-fire-and-forget-2. If you change layout, update this section.

Solution root
- src/
  - S7_Csharp_Utility/                        (main Avalonia app project)
    - Behaviors/
    - Commands/
    - Controls/
    - Converters/
    - Extensions/
    - Interfaces/
    - Models/
    - Resources/
    - Services/
    - ViewModels/
    - Views/
    - App.axaml
    - App.axaml.cs
    - MainWindow.axaml
    - MainWindow.axaml.cs
    - Program.cs
    - S7_Csharp_Utility.csproj
    - ViewLocator.cs
  - S7_Csharp_Core/                           (core domain types, interfaces - recommended)
    - (place for IVirtualFileReader, Page DTO, domain services)
  - S7_Csharp_Services/                       (services: IO, serial, modbus, bootloader protocol)
    - Serial/
    - Modbus/
    - FileReaders/
    - MemoryMapped/
  - S7_Csharp_Infrastructure/                 (caching, logging adapters, DI helpers)
  - S7_Csharp_Tests/                          (unit and integration tests)
  - tools/                                    (scripts, helpers)

Notes:
- Current branch shows primary UI under src/S7_Csharp_Utility; core and services crates may be colocated in same project. For good separation, we recommend splitting Core and Services into individual projects if not already present.

---

## If any structural changes are required (recommendations and rationale)

1. Add explicit Core and Services projects if they don't exist
   - Why: clear DI boundaries, easier unit testing, smaller test targets.  
   - What to do: create `S7_Csharp_Core` (interfaces, DTOs) and `S7_Csharp_Services` (implementations). Move existing core interfaces and DTOs into Core, move IO/transport implementations into Services. Update S7_Csharp_Utility.csproj to reference these projects.

2. Add Infrastructure project for PageCache, caching primitives, and logging adapters
   - Why: avoids UI project getting non-UI concerns; central place for LRU cache and throttling.  
   - What to do: create `S7_Csharp_Infrastructure` project and implement `PageCache`, cache configuration, and logging wrappers.

3. Tests separation
   - Why: CI faster and clearer test ownership.  
   - What to do: ensure `S7_Csharp_Tests` has unit tests targeting Core/Services/Infrastructure separately and integration tests that run higher-level flows.

4. If MemoryMappedFile use is planned, add platform-shim or fallback reader
   - Why: MMF on some environments (CI containers) can behave differently.  
   - What to do: implement `IVirtualFileReaderFactory` that yields `MemoryMappedFileVirtualReader` or `FileStreamVirtualReader` depending on runtime support.

If you adopt the above structural changes, update solution (.sln) to include new projects and update any CI scripts accordingly.

---

## What I inspected (files & focus)
- Primary UI project: src/S7_Csharp_Utility (ViewModels, Services, Controls).  
- AGENTS.md and branch metadata.  
- Common high-impact files: ViewModels (CTS plumbing, commands), Services (serial/bootloader), and virtualization code in Controls/Behaviors.  
- Note: I did not modify code; this file documents recommended changes and current statuses.

---

## Phases and status (items annotated for current branch)
Legend: Implemented / Partially implemented / Not implemented / Needs audit

Phase 0 — Stabilize current branch
- Convert non-framework async void to Task — Partially implemented; repo scan required (search for "async void")  
- FireAndForget helper + test + Notification routing — Implemented for main flows; add test coverage (Partially implemented)

Phase 1 — Command ergonomics and CTS patterns
- AsyncRelayCommand StartX wrappers and Start/Cancel patterns — Partially implemented (primary flows updated)  
- VM Dispose/DisposeAsync cancel CTS and clean-up — Needs audit; ensure no CTS leaks (Partially implemented)

Phase 2 — Service cancellation audit
- Bootloader/Serial/File public operations accept CancellationToken — Partially implemented (file reads mostly updated; transport/serial have blocking patterns)  
- ConfigureAwait(false) in non-UI libraries — Partially implemented; audit remaining services

Phase 3 — IVirtualFileReader + PageCache + Hex viewer wiring (next work)
- IVirtualFileReader interface and Page DTO — Not implemented (PR-2)  
- MemoryMappedFileVirtualReader and fallback — Not implemented (PR-3)  
- PageCache with dedupe/throttle/LRU — Not implemented (PR-4)  
- Unit + integration tests for dedupe/cancel/throttle — Not implemented (PR-4 tests)

Phase 4 — Hex viewer integration & UI polish
- Replace direct file reads with IVirtualFileReader + placeholders; IProgress plumbing — Partially implemented (placeholder concept present; integration missing)  
- Precomputed hex table, virtualization settings — Partially implemented

Phase 5 — Logging, tests, CI, polish
- Centralize structured logging, add CI jobs, async-void guard — Not implemented (CI missing for this branch)  
- Add build artifacts / packaging pipeline — Not implemented

Phase 6 — Micro-optimizations & feature parity
- Performance, benchmarks, stress tests — Not implemented

---

## Immediate prep checklist (do these before Phase 3 branch)
1. Repo scan and fix "async void" occurrences — convert to Task.  
2. Ensure ViewModels cancel CTS on Dispose/DisposeAsync.  
3. Add CancellationToken to long-lived public methods used by hex viewer and bootloader flows.  
4. Add a small FireAndForget unit test that asserts exceptions are routed to NotificationService.

---

## Phase 3 plan (high level, for copy/paste into PR descriptions)
- PR-1: repo hygiene — async void fixes, FireAndForget test, scripts/find_async_void.sh.  
- PR-2: Core/IVirtualFileReader + Core/Page DTO + interface tests.  
- PR-3: Services/MemoryMappedFileVirtualReader + fallback FileStream reader + tests.  
- PR-4: Infrastructure/PageCache (dedupe, throttle, LRU) + unit tests.  
- PR-5: Presentation/HexViewerViewModel wiring to IVirtualFileReader + placeholder UI + integration test with synthetic file.  
- PR-6: Metrics/logging and small perf tweaks (precomputed hex table).

Acceptance: PR-2..PR-5 merged, unit + integration tests pass, demo shows smooth scroll for synthetic large file.

---

## Developer hints and conventions
- Use ReadOnlyMemory<byte> or ImmutableArray<byte> for Page data to avoid mutable shared arrays.  
- Use ConcurrentDictionary<long, Task<Page>> for dedupe pattern; remove entry on cancel/failure.  
- Throttle parallel reads using SemaphoreSlim and make limit configurable.  
- Prefer DI registration in Program.cs (S7_Csharp_Utility) using Microsoft.Extensions.DependencyInjection.  
- Keep UI-free service projects: Services must expose IProgress<T> for progress and never call UI dispatcher directly.

---

## Where to add new files (recommended relative paths)
- Core/IVirtualFileReader.cs  
- Core/Page.cs  
- Services/IO/MemoryMappedFileVirtualReader.cs  
- Infrastructure/Caching/PageCache.cs  
- Tests/VirtualizationTests/PageCacheTests.cs  
- scripts/find_async_void.sh  
- .copilot-tracking/changes/<date>-phase3-virtualization-changes.md

---

## Quick references (commands)
- Build: dotnet build src/S7_Csharp_Utility/S7_Csharp_Utility.csproj -c Release -f net8.0  
- Run tests: dotnet test src/S7_Csharp_Tests --no-build

---

## Notes on structural changes I recommended (explanations)
- Splitting Core/Services/Infrastructure reduces coupling and speeds up tests. Move interfaces/DTOs to Core, implementations to Services, caching and adapters to Infrastructure. Update S7_Csharp_Utility project references.  
- Add IVirtualFileReaderFactory to allow runtime selection of MMF vs FileStream readers to avoid CI/OS pitfalls.  
- Add small synthetic-file test helper for integration tests (temp file >100MB with deterministic pattern).

---

## Final remark
Commit the AGENTS.md file above as-is to the branch feature/cancellation-and-fire-and-forget-2. After that, create the phase3/virtualization branch and follow the PR order in Phase 3 plan.
