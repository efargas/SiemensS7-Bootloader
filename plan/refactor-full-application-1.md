---
goal: 'Refactor the entire application to align with modern .NET best practices'
version: '2.0'
date_created: '2025-09-30'
last_updated: '2025-10-01'
owner: 'Jules'
status: 'Proposed'
tags: ['refactor', 'architecture', 'performance', 'ui', 'mvvm', 'security']
---

# Introduction

![Status: Proposed](https://img.shields.io/badge/status-Proposed-blue)

This implementation plan outlines a comprehensive refactoring of the application based on the findings in the `dotnet_best_practices_review.md` document and a subsequent in-depth code review. The goal is to modernize the codebase by addressing critical issues in resource management, error handling, security, and performance, while standardizing on architectural patterns like MVVM and Dependency Injection to improve overall code quality and maintainability.

## 1. Requirements & Constraints

- **REQ-001**: All classes managing unmanaged resources must correctly implement the `IDisposable` pattern.
- **REQ-002**: All business logic must be extracted from the UI/ViewModel layer into dedicated, testable services.
- **REQ-003**: A Dependency Injection (DI) container must be implemented to manage the lifecycle of all services and viewmodels.
- **REQ-004**: All logging must be standardized on the `Microsoft.Extensions.Logging.ILogger` interface.
- **REQ-005**: All "magic values" (hardcoded strings and numbers) must be centralized into constants classes.
- **REQ-006**: Outdated or insecure components (e.g., MD5 hashing) must be replaced with modern, secure alternatives (e.g., SHA-256).
- **REQ-007**: Performance-critical code paths should be optimized to reduce memory allocations and improve concurrency.
- **REQ-008**: Critical exceptions must not be swallowed; they should be re-thrown to ensure failures are visible.
- **CON-001**: All existing functionality must be preserved. The refactoring should not introduce regressions.

## 2. Implementation Steps

### Implementation Phase 1: Critical Fixes (Resource Management & Error Handling)

- GOAL-001: Address critical resource leaks and stabilize low-level communication by fixing error handling.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update `ICommunicationChannel` to inherit from `IDisposable`. | ✅ | 2025-10-01 |
| TASK-002 | Implement the full `IDisposable` pattern in `TcpChannel` and `SerialChannel` to ensure underlying resources are properly disposed. | ✅ | 2025-10-01 |
| TASK-003 | Refactor `PlcClient` to consistently re-throw critical exceptions like `ChecksumMismatchException` instead of swallowing them. | ✅ | 2025-10-01 |
| TASK-004 | Implement `IDisposable` on `PlcClient` to provide a standard mechanism for lifecycle management. | ✅ | 2025-10-01 |

### Implementation Phase 2: Architectural Refactoring (DI & MVVM)

- GOAL-002: Decouple all components by introducing a DI container and enforcing a clean MVVM architecture.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Create an `IConfigurationService` interface for `ConfigurationService`. | ✅ | 2025-10-01 |
| TASK-006 | Create an `IPowerController` interface and move it to its own file in the `Interfaces` directory. | ✅ | 2025-10-01 |
| TASK-007 | Create new services (`IExploitOrchestrationService`, `IConfigurationManagementService`, `IFileSystemService`) to encapsulate business logic currently in `MainWindowViewModel`. | ✅ | 2025-10-01 |
| TASK-008 | Refactor `MainWindowViewModel` to be a "lean" presentation class that delegates all business logic to the new, injected services. | ✅ | 2025-10-01 |
| TASK-009 | Refactor all DI registrations in `App.axaml.cs` to use interfaces instead of concrete types. | ✅ | 2025-10-01 |
| TASK-010 | Refactor the DI container setup in `App.axaml.cs` to build the `ServiceProvider` only once, resolving the logging provider issue. | ✅ | 2025-10-01 |

### Implementation Phase 3: Code Quality and Maintainability

- GOAL-003: Improve code clarity and reduce technical debt by centralizing constants and purifying data models.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | Create a dedicated `PlcConstants` class and move all magic strings and numbers from `PlcClient` into it. | ✅ | 2025-10-01 |
| TASK-012 | Refactor `S7UpdateUnpacker` and its legacy C-style `LzpDecompressor` to use modern C# idioms, improving readability and safety. | ✅ | 2025-10-01 |
| TASK-013 | Refactor `ApplicationConfiguration` to be a pure POCO model by moving all path resolution and default creation logic into `ConfigurationService`. | ✅ | 2025-10-01 |

### Implementation Phase 4: Utility Layer and Performance Improvements

- GOAL-004: Enhance the security and performance of the utility and networking layers.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-014 | In `DumpComparer.cs`, replace the MD5 hashing algorithm with SHA-256. | ✅ | 2025-10-01 |
| TASK-015 | Refactor `DumpComparer.cs` to parallelize file hashing using `Task.WhenAll`. | ✅ | 2025-10-01 |
| TASK-016 | Refactor `PlcProtocol` and `ProtocolUtils` to use `ArrayPool<byte>` and `Span<T>` to reduce memory allocations during packet encoding/decoding. | ✅ | 2025-10-01 |
| TASK-017 | Refactor `S7UpdateUnpacker` to use pooled arrays to reduce memory pressure when decompressing large firmware files. | ✅ | 2025-10-01 |
| TASK-018 | Fix the potential memory leak in `PageCache` by removing entries from the `_inflight` dictionary after a successful fetch. | ✅ | 2025-10-01 |

### Implementation Phase 5: Logging Standardization

- GOAL-005: Unify all application logging into a single, standard framework.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-019 | Refactor all classes currently using `Action<string>` or `Debug.WriteLine` to accept an `ILogger` via their constructor. | ✅ | 2025-10-01 |
| TASK-020 | Refactor `PlcClient` and command handlers to use `ILoggerFactory` to create typed loggers. | ✅ | 2025-10-01 |
| TASK-021 | Create a custom `UiLoggerProvider` to route log messages from `ILogger` to a dedicated `LogViewModel` for display in the UI. | ✅ | 2025-10-01 |
| TASK-022 | Register the `UiLoggerProvider` in the DI container and remove all legacy logging services. | ✅ | 2025-10-01 |
| TASK-023 | Add structured logging to `ConfigurationService` to provide better diagnostics for file I/O errors. | ✅ | 2025-10-01 |

## 3. Alternatives

- **ALT-001**: **"Big Bang" Refactoring**: The previous attempt to apply all fixes at once resulted in a broken build. This was rejected in favor of a more structured, phased approach.

## 4. Dependencies

- **DEP-001**: Requires adding the `Microsoft.Extensions.DependencyInjection` and `Microsoft.Extensions.Logging` NuGet packages to the `S7_Csharp_Utility` project.
- **DEP-002**: Requires adding the `Microsoft.Extensions.Logging.Abstractions` package to the `S7.Net` project.

## 5. Testing

- **TEST-001**: A comprehensive suite of unit tests should be created for the new service layer to ensure the correctness of the extracted business logic.
- **TEST-002**: Existing tests in `S7.Tests` must be reviewed and updated to reflect the changes in the core libraries.
- **TEST-003**: Manual, full-regression testing of the UI application is required to ensure no functionality was broken during the refactoring.

## 6. Risks & Assumptions

- **RISK-001**: The scope of this refactoring is large and touches many parts of the application, which increases the risk of introducing regressions. **Mitigation**: A phased approach and thorough testing (both automated and manual) are critical.
- **ASSUMPTION-001**: It is assumed that all core business logic is contained within the `src` directory and that no external dependencies have hidden business logic.

## 7. Related Specifications / Further Reading

- [dotnet_best_practices_review.md](file://dotnet_best_practices_review.md)