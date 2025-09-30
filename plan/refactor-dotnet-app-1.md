---
goal: 'Implement fixes and improvements based on the .NET Best Practices Review'
version: '1.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Planned'
tags: ['refactor', 'chore', 'architecture', 'performance', 'bug']
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan outlines the steps required to address the findings from the `dotnet_best_practices_review.md` report. The goal is to refactor the existing codebase to improve resource management, error handling, performance, and overall code quality by adhering to modern .NET best practices.

## 1. Requirements & Constraints

- **REQ-001**: Implement `IDisposable` on classes managing unmanaged resources (e.g., `ICommunicationChannel`) to prevent resource leaks.
- **REQ-002**: Ensure consistent and robust error handling strategies across the application, replacing generic exceptions with specific ones where applicable.
- **REQ-003**: Eliminate all "magic values" (hardcoded strings and numbers) by centralizing them in dedicated constants classes.
- **REQ-004**: Replace outdated cryptographic algorithms (MD5) with modern, secure alternatives (SHA-256).
- **REQ-005**: Optimize performance-critical code paths, including parallelizing I/O-bound operations and reducing unnecessary memory allocations.
- **REQ-006**: Adhere strictly to the Inversion of Control (IoC) principle by using dependency injection for all dependencies instead of direct instantiation.
- **CON-001**: All changes must be covered by existing or new unit tests to prevent regressions.

## 2. Implementation Steps

### Implementation Phase 1: Resource Management & Error Handling

- GOAL-001: Fix critical resource leaks and standardize exception handling in the data access layer.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Implement `IDisposable` in `S7.Net/PlcClient.cs` to properly dispose of the underlying `ICommunicationChannel`. | | |
| TASK-002 | Implement `IDisposable` in `S7.Net/PlcProtocol.cs` to ensure its resources are managed correctly. | | |
| TASK-003 | Update `S7.Core.Commands/MemoryDumpCommandHandler.cs` to wrap the `ICommunicationChannel` instance in a `using` block. | | |
| TASK-004 | Refactor `S7.Net/PlcClient.cs` to handle `ChecksumMismatchException` consistently, re-throwing it instead of returning null or logging-and-continuing. | | |

### Implementation Phase 2: Code Quality and Constants

- GOAL-002: Improve maintainability by refactoring hardcoded values into constants.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Move all magic values (e.g., "MFGT1", subprotocol constants) from `S7.Net/PlcClient.cs` to `S7.Net/PlcConstants.cs`. | | |
| TASK-006 | Create a new constants class within `S7.Utils` and move the magic string `"A00000"` from `S7.Utils/S7UpdateUnpacker.cs` into it. | | |

### Implementation Phase 3: Utility Layer Improvements

- GOAL-003: Enhance the performance and security of the utility library.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | In `S7.Utils/DumpComparer.cs`, replace the `MD5.Create()` implementation with `SHA256.Create()`. | | |
| TASK-008 | Modify `S7.Utils/DumpComparer.cs` to process files in parallel using `Task.WhenAll` to speed up hashing. | | |
| TASK-009 | Modify `S7.Utils/S7UpdateUnpacker.cs` and `LzpDecompressor` to accept an array segment or offset, avoiding the `.Skip(2).ToArray()` allocation in the unpack loop. | | |

### Implementation Phase 4: Dependency Injection Refactoring

- GOAL-004: Decouple components by applying IoC principles throughout the application.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-010 | Refactor `S7.Core.Commands/MemoryDumpCommandHandler.cs` to accept an `ICommunicationChannelFactory` via DI instead of creating channels directly. | | |
| TASK-011 | Convert the static `S7.Services/VirtualFileReaderFactory.cs` into an instance-based service (`IVirtualFileReaderFactory`) that can be registered in a DI container. | | |

## 3. Alternatives

- **ALT-001**: **Do Nothing**: Deferring the refactoring was considered. This was rejected as the identified issues (resource leaks, potential data corruption, security vulnerabilities) pose a significant risk to application stability and security.
- **ALT-002**: **Fix Critical Issues Only**: A minimal approach focusing only on resource leaks was considered. This was rejected in favor of a comprehensive refactoring to maximize the long-term health and maintainability of the codebase.

## 4. Dependencies

- **DEP-001**: The refactoring relies on the existing .NET Core SDK and the project structure. No new external NuGet packages are required.

## 5. Files

- **FILE-001**: `src/S7_Csharp_Core/S7.Net/PlcClient.cs`
- **FILE-002**: `src/S7_Csharp_Core/S7.Net/PlcProtocol.cs`
- **FILE-003**: `src/S7_Csharp_Core/S7.Net/PlcConstants.cs`
- **FILE-004**: `src/S7_Csharp_Core/S7.Core.Commands/MemoryDumpCommandHandler.cs`
- **FILE-005**: `src/S7_Csharp_Core/S7.Utils/S7UpdateUnpacker.cs`
- **FILE-006**: `src/S7_Csharp_Core/S7.Utils/DumpComparer.cs`
- **FILE-007**: `src/S7_Csharp_Core/S7.Services/VirtualFileReaderFactory.cs`
- **FILE-008**: All relevant test files associated with the above source files.

## 6. Testing

- **TEST-001**: All existing unit tests must pass after the refactoring.
- **TEST-002**: Update tests for `DumpComparer` to validate SHA-256 hashes instead of MD5.
- **TEST-003**: Add tests for the new `ICommunicationChannelFactory` and `IVirtualFileReaderFactory` to ensure they are correctly creating instances.
- **TEST-004**: Add tests to verify that `IDisposable` is called correctly on `PlcClient` and `PlcProtocol`.

## 7. Risks & Assumptions

- **RISK-001**: The refactoring of low-level communication logic could introduce subtle behavioral changes or race conditions. Mitigation: Thorough testing and validation against a real or simulated PLC environment.
- **ASSUMPTION-001**: It is assumed that the existing test suite provides adequate coverage for the current functionality. If not, new tests may be required to prevent regressions.

## 8. Related Specifications / Further Reading

- [dotnet_best_practices_review.md](file://dotnet_best_practices_review.md)