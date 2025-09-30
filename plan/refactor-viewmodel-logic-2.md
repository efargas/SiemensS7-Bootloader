---
goal: 'Complete UI refactoring by extracting all remaining business logic from ViewModels'
version: '2.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Planned'
tags: ['refactor', 'ui', 'mvvm', 'architecture']
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan outlines the final set of tasks to complete the UI layer refactoring. The goal is to extract all remaining business and orchestration logic from the viewmodels, ensuring they are lean and focused purely on presentation state. This will be achieved by creating new services to handle application state management and system interactions.

## 1. Requirements & Constraints

- **REQ-001**: All application state management (loading/saving configuration, applying profiles) must be handled by a dedicated service, not the `MainWindowViewModel`.
- **REQ-002**: All direct interaction with system resources (e.g., querying serial ports) must be abstracted behind a service interface.
- **REQ-003**: Service classes (e.g., `SocatService`) should encapsulate their own operational logic (e.g., checking for running processes) rather than having this logic live in a viewmodel.
- **REQ-004**: All new and modified services and viewmodels must use dependency injection.

## 2. Implementation Steps

### Implementation Phase 1: Create New Services

- GOAL-001: Abstract all remaining business logic into new, dedicated services.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Create a new `IApplicationStateService` interface with methods for loading and saving the application's configuration and profiles. | | |
| TASK-002 | Create an `ApplicationStateService` class that implements `IApplicationStateService` and contains the logic currently in `MainWindowViewModel` for managing application state. | | |
| TASK-003 | Create a new `ISerialPortService` interface with a method to get available serial port names. | | |
| TASK-004 | Create a `SerialPortService` class that implements `ISerialPortService` and contains the logic for querying `System.IO.Ports.SerialPort.GetPortNames()`. | | |

### Implementation Phase 2: Refactor ViewModels and Services

- GOAL-002: Update existing viewmodels and services to use the new abstractions.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Refactor `MainWindowViewModel` to inject and use `IApplicationStateService`. The `LoadConfigurationOnStartup` and `SaveConfigurationOnExitAsync` methods will be replaced with simple calls to the new service. | | |
| TASK-006 | Refactor `PlcConnectionViewModel` to inject and use `ISerialPortService` for refreshing the list of available serial ports. | | |
| TASK-007 | Refactor `SocatService` to include methods for checking and killing its own processes, removing this logic from `PlcConnectionViewModel`. | | |
| TASK-008 | Update `PlcConnectionViewModel` to call the new methods on `SocatService`. | | |

### Implementation Phase 3: Update Dependency Injection

- GOAL-003: Register all new services with the dependency injection container.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | In `App.axaml.cs`, register `IApplicationStateService` and `ISerialPortService` with the DI container. | | |
| TASK-010 | Update the constructor registrations for `MainWindowViewModel` and `PlcConnectionViewModel` to include their new service dependencies. | | |

## 3. Alternatives

- **ALT-001**: **Leave as is**: Rejected. While the application is functional, leaving business logic in the viewmodels goes against the architectural goals, making the code harder to test and maintain.

## 4. Dependencies

- **DEP-001**: This plan depends on the successful completion of all tasks in `plan/refactor-ui-logic-1.md`.

## 5. Files

- **FILE-001**: `src/S7_Csharp_Utility/ViewModels/MainWindowViewModel.cs`
- **FILE-002**: `src/S7_Csharp_Utility/ViewModels/PlcConnectionViewModel.cs`
- **FILE-003**: `src/S7_Csharp_Utility/Services/SocatService.cs`
- **FILE-004**: `src/S7_Csharp_Utility/App.axaml.cs`
- **FILE-005**: (New) `src/S7_Csharp_Utility/Interfaces/IApplicationStateService.cs`
- **FILE-006**: (New) `src/S7_Csharp_Utility/Services/ApplicationStateService.cs`
- **FILE-007**: (New) `src/S7_Csharp_Utility/Interfaces/ISerialPortService.cs`
- **FILE-008**: (New) `src/S7_Csharp_Utility/Services/SerialPortService.cs`

## 6. Testing

- **TEST-001**: All existing UI functionality (config loading/saving, serial port refreshing) must remain intact.
- **TEST-002**: New unit tests should be created for the new service classes (`ApplicationStateService`, `SerialPortService`) to verify their logic.

## 7. Risks & Assumptions

- **RISK-001**: Refactoring the application state management could introduce subtle bugs in how configuration is loaded or saved. **Mitigation**: Thoroughly test all application startup and shutdown sequences.

## 8. Related Specifications / Further Reading

- [plan/refactor-ui-logic-1.md](file://plan/refactor-ui-logic-1.md)