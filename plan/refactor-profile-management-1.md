---
goal: 'Extract profile management logic from ProfileManagementViewModel into a dedicated service'
version: '1.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Planned'
tags: ['refactor', 'ui', 'mvvm', 'final']
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan outlines the final refactoring task to achieve a pure MVVM architecture. The goal is to extract all remaining business logic from the `ProfileManagementViewModel` into a dedicated `IProfileManagerService`. This will make the viewmodel a lean presentation-only class and complete the separation of concerns in the UI layer.

## 1. Requirements & Constraints

- **REQ-001**: All profile lifecycle management (loading, saving, creating, deleting) must be handled by the new `IProfileManagerService`.
- **REQ-002**: The `ProfileManagementViewModel` must be refactored to delegate all profile-related operations to the new service. It should only manage the state of the UI (e.g., the list of profiles, the selected profile).
- **REQ-003**: The new service must be registered with the dependency injection container and injected into the viewmodel.

## 2. Implementation Steps

### Implementation Phase 1: Service Creation

- GOAL-001: Create a new service to encapsulate all profile management logic.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Create a new `IProfileManagerService` interface with methods like `GetAllProfilesAsync`, `SaveProfileAsync`, `DeleteProfileAsync`, and `CreateNewProfile`. | | |
| TASK-002 | Create a `ProfileManagerService` class that implements `IProfileManagerService` and moves all profile management logic from `ProfileManagementViewModel`. | | |

### Implementation Phase 2: ViewModel Refactoring

- GOAL-002: Refactor `ProfileManagementViewModel` to be a pure presentation class.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-003 | Refactor `ProfileManagementViewModel` to inject and use `IProfileManagerService`. All commands (Add, Delete, Save) will now call methods on the new service. | | |

### Implementation Phase 3: Dependency Injection Setup

- GOAL-003: Integrate the new profile management service into the application's DI container.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | In `App.axaml.cs`, register `IProfileManagerService` and its concrete implementation with the DI container. | | |
| TASK-005 | Update the `ProfileManagementViewModel` registration to inject the new `IProfileManagerService`. | | |

## 3. Alternatives

- **ALT-001**: **Leave as is**: Rejected. This is the final and necessary step to achieve the architectural goal of clean separation of concerns.

## 4. Dependencies

- **DEP-001**: This plan depends on the successful completion of all tasks in `plan/refactor-ui-logic-1.md`.

## 5. Files

- **FILE-001**: `src/S7_Csharp_Utility/ViewModels/ProfileManagementViewModel.cs`
- **FILE-002**: `src/S7_Csharp_Utility/App.axaml.cs`
- **FILE-003**: (New) `src/S7_Csharp_Utility/Interfaces/IProfileManagerService.cs`
- **FILE-004**: (New) `src/S7_Csharp_Utility/Services/ProfileManagerService.cs`

## 6. Testing

- **TEST-001**: All existing profile management functionality must remain intact.
- **TEST-002**: New unit tests should be created for the new `ProfileManagerService` to verify its logic independently of the UI.

## 7. Risks & Assumptions

- **RISK-001**: None. This is a low-risk, well-contained refactoring.

## 8. Related Specifications / Further Reading

- [plan/refactor-ui-logic-1.md](file://plan/refactor-ui-logic-1.md)