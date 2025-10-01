# Copilot Instructions for SiemensS7-Bootloader

## Project Overview
- **Purpose:** Cross-platform .NET (Avalonia UI) utility for interacting with Siemens S7 PLC bootloaders, supporting binary/hex image inspection, editing, comparison, and upload. Robustness, responsiveness with large files, and extensibility are key.
- **Architecture:** MVVM pattern with clear separation:
  - **UI:** Avalonia XAML views, minimal code-behind.
  - **ViewModels:** Orchestrate commands, manage CancellationTokenSource, marshal UI progress.
  - **Services:** All async-first, cancellation-aware; handle protocol, file, and transport I/O.
  - **Infrastructure:** Logging, concurrency, caching, DI.
  - **Core Domain:** Pure logic (hex formatting, diff/search, checksum), unit-tested.

## Key Patterns & Conventions
- **Async/Cancellation:**
  - All long-running methods are async and accept CancellationToken.
  - Use `ConfigureAwait(false)` in non-UI code.
  - No non-framework `async void` (use `Task`-returning methods).
  - Fire-and-forget tasks use `TaskExtensions.FireAndForget` and log exceptions via `INotificationService`.
- **Commands:**
  - Use `AsyncRelayCommand` or VM `StartX` wrappers for commands needing cancellation.
  - `ICommand.Execute` is a thin async void wrapper calling a Task-returning method.
  - ViewModels own and dispose their CTS.
- **Hex Viewer:**
  - Data/UI virtualization: rows are loaded on demand, placeholder rows shown while loading.
  - Backed by MMF and page cache (deduplication via `ConcurrentDictionary<long, Task<Page>>`, throttled with `SemaphoreSlim`, LRU eviction).
  - Precompute byte-to-hex string table for rendering.
  - Search scans with page overlap to avoid boundary misses.
- **Testing & CI:**
  - Unit tests for pure logic and concurrency behaviors (cancellation, dedupe, search).
  - CI enforces no stray `async void` and runs `dotnet format`.

## Developer Workflows
- **Build:**
  - `dotnet build src/S7_Csharp_Utility/S7_Csharp_Utility.csproj --configuration Release`
- **Run:**
  - Linux: `./S7_CS_Utility` from output dir
  - Windows: `.\\S7_CS_Utility.exe`
- **Payloads:**
  - Build ARM payloads: `cd bootloader-payloads/docker-scripts && ./extract_payloads.sh [output_dir]`
  - Clean Docker: `./cleanup_docker.sh`
- **Legacy Tools:**
  - Modbus server: `python3 Legacy/tools/modbus_server.py` (requires `pymodbus`)
  - Power supply: see `Legacy/tools/powersupply/`

## Integration Points
- **Serial-to-TCP:** Use `socat` to forward serial to TCP for PLC connection.
- **Modbus Power:** App controls power via Modbus/TCP (configurable in UI).
- **Payloads:** `.bin` files from `bootloader-payloads/payloads/` are uploaded to PLCs.

## References
- See `AGENTS.md` for architecture, conventions, and phased refactor plan.
- See `README.md` for usage, device details, and protocol overview.
- See `bootloader-payloads/README.md` for payload build details.

---
**Example:**
- To add a new I/O service, implement async methods with CancellationToken, use `ConfigureAwait(false)`, and ensure exceptions are logged via `INotificationService`.
- For new ViewModels, manage CTS lifecycle and expose commands via `AsyncRelayCommand`.
