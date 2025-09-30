---
goal: 'Refactor UI layer to separate business logic from ViewModels'
version: '1.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Planned'
tags: ['refactor', 'ui', 'mvvm', 'architecture']
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan outlines the steps required to refactor the UI layer of the `S7_Csharp_Utility` project. The primary goal is to enforce a clean separation of concerns by moving business logic out of the viewmodels and into dedicated services, adhering strictly to the MVVM pattern. This will improve testability, maintainability, and the overall architecture of the application.

## 1. Requirements & Constraints

- **REQ-001**: Business logic (e.g., file operations, data processing, service orchestration) must be removed from viewmodels.
- **REQ-002**: Viewmodels must not have any direct knowledge of or reference to any View class. All view creation and presentation must be handled by a dedicated service (e.g., `IViewService`).
- **REQ-003**: All dependencies, including services and loggers, must be provided to viewmodels via dependency injection. Viewmodels should not create their own service instances.
- **REQ-004**: Asynchronous operations in viewmodels must be handled using a robust async command pattern (e.g., `AsyncRelayCommand`) that properly manages `Task`-based methods.
- **REQ-005**: All logging within the `S7_Csharp_Utility` project should be standardized on the `Microsoft.Extensions.Logging.ILogger` interface.
- **CON-001**: A dependency injection container must be set up to manage the lifecycle and resolution of all services and viewmodels.

## 2. Implementation Steps

### Implementation Phase 1: Service Layer Creation

- GOAL-001: Create new services to encapsulate business logic currently in viewmodels.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Create a new `IFirmwareUnpackingService` interface with methods for parsing firmware metadata and unpacking firmware files. | | |
| TASK-002 | Create a `FirmwareUnpackingService` class that implements `IFirmwareUnpackingService` and contains the logic currently in `FirmwareUnpackerViewModel`. | | |
| TASK-003 | Create a new `IFileComparisonService` interface with methods for comparing files in a folder and generating a report. | | |
| TASK-004 | Create a `FileComparisonService` class that implements `IFileComparisonService` and contains the logic currently in `FileCompareViewModel`. | | |

### Implementation Phase 2: ViewModel Refactoring

- GOAL-002: Refactor existing viewmodels to delegate work to the new services and remove all business and view logic.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Refactor `FirmwareUnpackerViewModel` to inject and use `IFirmwareUnpackingService`. Remove direct instantiation of `S7UpdateUnpacker`. | | |
| TASK-006 | Refactor `FileCompareViewModel` to inject and use `IFileComparisonService`. Remove direct instantiation of `DumpComparer`. | | |
| TASK-007 | Remove all view creation logic (e.g., `new Views.DiffView()`) from `FileCompareViewModel`. Update it to use the `IViewService` to show dialogs or navigate. | | |
| TASK-008 | Refactor `FileCompareViewModel` to use the standard `ILogger` interface instead of the custom `LoggingService`. | | |

### Implementation Phase 3: Dependency Injection Setup

- GOAL-003: Establish a dependency injection container to manage the application's object graph.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | Integrate a DI container (e.g., `Microsoft.Extensions.DependencyInjection`) into the `S7_Csharp_Utility` project, likely in `App.axaml.cs` or `Program.cs`. | | |
| TASK-010 | Register all services (`IFirmwareUnpackingService`, `IFileComparisonService`, `IDialogService`, `IViewService`, `ILogger`, etc.) and viewmodels with the DI container. | | |
| TASK-011 | Update the application's startup logic and `ViewLocator` to resolve viewmodels and their dependencies from the DI container instead of manual instantiation. | | |

## 3. Alternatives

- **ALT-001**: **Manual Dependency Management**: Continue instantiating dependencies manually. This was rejected because it leads to tightly coupled code that is difficult to test and maintain, which is the core problem this refactoring aims to solve.

## 4. Dependencies

- **DEP-001**: Requires the `Microsoft.Extensions.DependencyInjection` and `Microsoft.Extensions.Logging` NuGet packages.

## 5. Files

- **FILE-001**: `src/S7_Csharp_Utility/ViewModels/FirmwareUnpackerViewModel.cs`
- **FILE-002**: `src/S7_Csharp_Utility/ViewModels/FileCompareViewModel.cs`
- **FILE-003**: `src/S7_Csharp_Utility/App.axaml.cs`
- **FILE-004**: `src/S7_Csharp_Utility/Program.cs`
- **FILE-005**: `src/S7_Csharp_Utility/ViewLocator.cs`
- **FILE-006**: (New) `src/S7_Csharp_Utility/Interfaces/IFirmwareUnpackingService.cs`
- **FILE-007**: (New) `src/S7_Csharp_Utility/Services/FirmwareUnpackingService.cs`
- **FILE-008**: (New) `src/S7_Csharp_Utility/Interfaces/IFileComparisonService.cs`
- **FILE-009**: (New) `src/S7_Csharp_Utility/Services/FileComparisonService.cs`

## 6. Testing

- **TEST-001**: All existing UI functionality must remain intact.
- **TEST-002**: New unit tests should be created for the new service classes (`FirmwareUnpackingService`, `FileComparisonService`) to verify their logic independently of the UI.

## 7. Risks & Assumptions

- **RISK-001**: Integrating a DI container into an existing Avalonia UI application can be complex and may require significant changes to the startup and view location logic. **Mitigation**: Follow established patterns for DI in Avalonia and test the application startup thoroughly.
- **ASSUMPTION-001**: It is assumed that the current `IViewService` and `IDialogService` abstractions are sufficient and will not need significant changes to support the refactored viewmodels.

## 8. Related Specifications / Further Reading

- [plan/refactor-dotnet-app-2.md](file://plan/refactor-dotnet-app-2.md)