---
goal: 'Implement final architectural refinements for performance and purity'
version: '3.0'
date_created: '2025-09-30'
last_updated: '2025-09-30'
owner: 'Jules'
status: 'Planned'
tags: ['refactor', 'performance', 'architecture', 'final']
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan outlines the final set of architectural refinements for the application. The goals are to maximize performance in the low-level communication layer by eliminating memory allocations, ensure architectural purity by making model classes pure POCOs, and improve the design of the `PlcClient` by applying the Interface Segregation Principle.

## 1. Requirements & Constraints

- **REQ-001**: The `ApplicationConfiguration` class must be a pure POCO (Plain Old CLR Object) with no business logic.
- **REQ-002**: All path resolution and default configuration logic must be centralized in the `ConfigurationService`.
- **REQ-003**: The `PlcProtocol` service must use buffer pooling to eliminate memory allocations in its send/receive hot paths.
- **REQ-004**: The `PlcClient`'s functionality must be segregated into smaller, more focused interfaces.
- **REQ-005**: All services must use `ILogger` for logging.

## 2. Implementation Steps

### Implementation Phase 1: Configuration and Model Purity

- GOAL-001: Refactor `ApplicationConfiguration` into a pure POCO and move all related logic into `ConfigurationService`.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Move all static methods (`GetPayloadsPath`, `GetDefaultDumpsPath`, `ResolvePath`, `CreateDefault`) from `ApplicationConfiguration` into `ConfigurationService`. | | |
| TASK-002 | Make `ApplicationConfiguration` a pure POCO class by removing all method bodies and logic. | | |
| TASK-003 | Refactor `ConfigurationService` to inject and use `ILogger<ConfigurationService>`. | | |
| TASK-004 | Refactor `ConfigurationViewModel` to call the new methods on `ConfigurationService` to get default paths. | | |

### Implementation Phase 2: High-Performance Networking

- GOAL-002: Optimize the low-level communication protocol to minimize memory allocations.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Add a `SEND_PACKET_DELAY_MS` constant to `PlcConstants.cs` to replace the hardcoded `Task.Delay(10)`. | | |
| TASK-006 | Refactor `PlcProtocol` to use `ArrayPool<byte>.Shared` for renting and returning buffers in `SendPacketAsync` and `ReceivePacketAsync`, eliminating allocations. | | |

### Implementation Phase 3: Interface Segregation

- GOAL-003: Apply the Interface Segregation Principle to the `PlcClient` class.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Create a new `IPlcHandshakeManager` interface for the `PerformHandshakeAsync` method. | | |
| TASK-008 | Create a new `IPlcMemoryAccessor` interface for the `WriteToIram` and `DumpMemoryAsync` methods. | | |
| TASK-009 | Create a new `IPlcStagerController` interface for the `InstallStager`, `WriteViaStager`, and `InstallAddHookViaStager` methods. | | |
| TASK-010 | Make `PlcClient` implement the new `IPlcHandshakeManager`, `IPlcMemoryAccessor`, and `IPlcStagerController` interfaces. | | |

### Implementation Phase 4: Final Integration

- GOAL-004: Update all consumers to use the new, more focused interfaces and services.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | Update command handlers (e.g., `StagerInstallCommandHandler`, `MemoryDumpCommandHandler`) to depend on the new, smaller interfaces (`IPlcStagerController`, `IPlcMemoryAccessor`) instead of the concrete `PlcClient` class. | | |
| TASK-012 | Update the DI container in `App.axaml.cs` to register the new interfaces, pointing them to the `PlcClient` implementation. | | |

## 3. Alternatives

- **ALT-001**: **Skip Performance Tuning**: This was rejected. The identified memory allocations in the communication layer are a significant performance risk for a high-frequency application and should be addressed proactively.

## 4. Dependencies

- **DEP-001**: This plan depends on the successful completion of all tasks in `plan/refactor-ui-logic-1.md`.

## 5. Files

- **FILE-001**: `src/S7_Csharp_Utility/Models/ApplicationConfiguration.cs`
- **FILE-002**: `src/S7_Csharp_Utility/Services/ConfigurationService.cs`
- **FILE-003**: `src/S7_Csharp_Utility/ViewModels/ConfigurationViewModel.cs`
- **FILE-004**: `src/S7_Csharp_Core/S7.Net/PlcProtocol.cs`
- **FILE-005**: `src/S7_Csharp_Core/S7.Net/PlcClient.cs`
- **FILE-006**: (New) `src/S7_Csharp_Core/S7.Net/Interfaces/IPlcHandshakeManager.cs`
- **FILE-007**: (New) `src/S7_Csharp_Core/S7.Net/Interfaces/IPlcMemoryAccessor.cs`
- **FILE-008**: (New) `src/S7_Csharp_Core/S7.Net/Interfaces/IPlcStagerController.cs`

## 6. Testing

- **TEST-001**: All existing functionality must remain intact.
- **TEST-002**: Performance tests could be added to verify the reduction in memory allocations in `PlcProtocol`.

## 7. Risks & Assumptions

- **RISK-001**: Refactoring the low-level packet handling to use `ArrayPool` can be complex and may introduce subtle bugs if not handled carefully. **Mitigation**: Thoroughly test all communication paths after the change.

## 8. Related Specifications / Further Reading

- [plan/refactor-viewmodel-logic-2.md](file://plan/refactor-viewmodel-logic-2.md)