---
goal: 'Refactor the entire application to align with modern .NET best practices'
version: '1.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Proposed'
tags: ['refactor', 'architecture', 'performance', 'ui', 'mvvm']
---

# Introduction

![Status: Proposed](https://img.shields.io/badge/status-Proposed-blue)

This implementation plan outlines a comprehensive refactoring of the application based on the findings in the `dotnet_best_practices_review.md` document. The goal is to modernize the codebase by addressing critical issues in resource management, standardizing on architectural patterns like MVVM and Dependency Injection, improving performance, and enhancing overall code quality and maintainability.

## 1. Requirements & Constraints

- **REQ-001**: All classes managing unmanaged resources must correctly implement the `IDisposable` pattern.
- **REQ-002**: All business logic must be extracted from the UI/ViewModel layer into dedicated, testable services.
- **REQ-003**: A Dependency Injection (DI) container must be implemented to manage the lifecycle of all services and viewmodels.
- **REQ-004**: All logging must be standardized on the `Microsoft.Extensions.Logging.ILogger` interface.
- **REQ-005**: All "magic values" (hardcoded strings and numbers) must be centralized into constants classes.
- **REQ-006**: Outdated or insecure components (e.g., MD5 hashing) must be replaced with modern, secure alternatives (e.g., SHA-256).
- **REQ-007**: Performance-critical code paths, especially in the networking layer, should be optimized to reduce memory allocations.
- **CON-001**: All existing functionality must be preserved. The refactoring should not introduce regressions.

## 2. Implementation Steps

### Implementation Phase 1: Critical Fixes (Resource Management & Error Handling)

- GOAL-001: Address critical resource leaks and stabilize low-level communication by fixing error handling.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update `ICommunicationChannel` to inherit from `IDisposable`. | | |
| TASK-002 | Implement the full `IDisposable` pattern in `TcpChannel` and `SerialChannel` to ensure underlying resources are properly disposed. | | |
| TASK-003 | Refactor `PlcClient` to consistently re-throw critical exceptions like `ChecksumMismatchException` instead of swallowing them. | | |

### Implementation Phase 2: Architectural Refactoring (DI & MVVM)

- GOAL-002: Decouple all components by introducing a DI container and enforcing a clean MVVM architecture.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Integrate `Microsoft.Extensions.DependencyInjection` into `App.axaml.cs` to create and manage a service provider. | | |
| TASK-005 | Create interfaces for all services (e.g., `IConfigurationService`, `IViewService`, `IPowerController`). | | |
| TASK-006 | Create new services (`IFirmwareUnpackingService`, `IFileComparisonService`, etc.) to encapsulate business logic currently in viewmodels. | | |
| TASK-007 | Refactor all viewmodels (`MainWindowViewModel`, `FileCompareViewModel`, etc.) to be lean presentation classes that delegate all business logic to the new, injected services. | | |
| TASK-008 | Remove all direct view instantiation from viewmodels (e.g., `new ComparisonResultWindow()`), and update `IViewService` to handle view resolution and presentation. | | |
| TASK-009 | Register all services and viewmodels with the DI container in `App.axaml.cs`. | | |

### Implementation Phase 3: Code Quality and Maintainability

- GOAL-003: Improve code clarity and reduce technical debt by centralizing constants and purifying data models.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-010 | Create dedicated constants classes (`PlcConstants`, `PayloadConstants`, etc.) and move all magic strings and numbers into them. | | |
| TASK-011 | Refactor `ApplicationConfiguration` to be a pure POCO model by moving all path resolution and default creation logic into `ConfigurationService`. | | |
| TASK-012 | Update all consumers of `ApplicationConfiguration` to use the refactored `ConfigurationService` for path and default logic. | | |

### Implementation Phase 4: Utility Layer and Performance Improvements

- GOAL-004: Enhance the security and performance of the utility and networking layers.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-013 | In `DumpComparer.cs`, replace the MD5 hashing algorithm with SHA-256. | | |
| TASK-014 | Refactor `DumpComparer.cs` to parallelize file hashing using `Task.WhenAll`. | | |
| TASK-015 | Refactor `PlcProtocol` to use `ArrayPool<byte>` for its send/receive buffers to reduce memory allocations. | | |

### Implementation Phase 5: Logging Standardization

- GOAL-005: Unify all application logging into a single, standard framework.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-016 | Refactor all classes currently using `Debug.WriteLine` or a custom logging service to accept an `ILogger` via their constructor. | | |
| TASK-017 | Create a custom `UiLoggerProvider` to route log messages from `ILogger` to a dedicated `LogViewModel` for display in the UI. | | |
| TASK-018 | Register the `UiLoggerProvider` in the DI container and remove all legacy logging services. | | |

## 3. Alternatives

- **ALT-001**: **Incremental Refactoring**: Applying fixes one by one without a holistic plan. This was rejected as it could lead to an inconsistent architecture and would be less efficient than a planned, phased approach.

## 4. Dependencies

- **DEP-001**: Requires adding the `Microsoft.Extensions.DependencyInjection` and `Microsoft.Extensions.Logging` NuGet packages to the `S7_Csharp_Utility` project.

## 5. Files

- This refactoring will touch a significant number of files across all projects in the `src` directory. Key files are listed in the task descriptions above.

## 6. Testing

- **TEST-001**: A comprehensive suite of unit tests should be created for the new service layer to ensure the correctness of the extracted business logic.
- **TEST-002**: Existing tests in `S7.Tests` should be reviewed and updated to reflect the changes in the core libraries.
- **TEST-003**: Manual, full-regression testing of the UI application is required to ensure no functionality was broken during the refactoring.

## 7. Risks & Assumptions

- **RISK-001**: The scope of this refactoring is large and touches many parts of the application, which increases the risk of introducing regressions. **Mitigation**: A phased approach and thorough testing (both automated and manual) are critical.
- **ASSUMPTION-001**: It is assumed that all core business logic is contained within the `src` directory and that no external dependencies have hidden business logic.

## 8. Related Specifications / Further Reading

- [dotnet_best_practices_review.md](file://dotnet_best_practices_review.md)