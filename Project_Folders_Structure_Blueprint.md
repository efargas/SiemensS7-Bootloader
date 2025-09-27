# Project Folders Structure Blueprint

*Last Updated: 2025-09-27*

This document serves as a definitive guide for maintaining consistent code organization within the Siemens S7 PLCs Bootloader Utility project.

### Initial Auto-detection Phase

The project has been identified as a **.NET 8** desktop application built with the **Avalonia UI** framework for cross-platform compatibility.

- **Project Type**: .NET
- **Microservices**: No. The project follows a monolithic architecture.
- **Frontend**: Yes, a desktop UI built with Avalonia. No web frontend.
- **Monorepo**: No. It is a single solution with multiple related projects.

### 1. Structural Overview

The project is organized using a **layered architecture**, which promotes a strong separation of concerns. The primary organizational principle is by technical layer, ensuring that UI, business logic, and data access are decoupled.

The structure is divided into two main parts:
- **`S7_Csharp_Core`**: A set of class libraries containing the core business logic, communication protocols, and abstractions. This part is completely independent of the UI.
- **`S7_Csharp_Utility`**: The presentation layer, which is a desktop application that consumes the functionality provided by the core libraries.

This design makes the core logic reusable and easier to test in isolation.

### 2. Directory Visualization

Below is an ASCII tree representation of the project's `src` directory.

```
src/
├── SiemensS7-Bootloader.sln
├── S7_Csharp_Core/
│   ├── S7.Core.Abstractions/
│   │   ├── Commands/
│   │   ├── Configuration/
│   │   ├── Factories/
│   │   ├── ...
│   │   └── S7.Core.Abstractions.csproj
│   ├── S7.Core.Commands/
│   │   ├── Handlers/
│   │   └── S7.Core.Commands.csproj
│   ├── S7.Infrastructure/
│   │   ├── Factories/
│   │   ├── Repositories/
│   │   └── S7.Infrastructure.csproj
│   ├── S7.Net/
│   │   ├── Channels/
│   │   └── S7.Net.csproj
│   ├── S7.Services/
│   │   └── S7.Services.csproj
│   └── S7.Utils/
│       └── S7.Utils.csproj
└── S7_Csharp_Utility/
    ├── ViewModels/
    │   ├── Features/
    │   └── ...
    ├── Views/
    ├── Services/
    ├── Resources/
    └── S7_Csharp_Utility.csproj
```

### 3. Key Directory Analysis

- **`src/`**: The root directory for all C# source code. It contains the Visual Studio solution file (`SiemensS7-Bootloader.sln`) that ties all the projects together.
- **`src/S7_Csharp_Core/`**: Contains the core logic of the application, organized into distinct layers.
  - **`S7.Core.Abstractions/`**: Defines the contracts (interfaces and abstract classes) for the application. This includes abstractions for services, repositories, commands, and configuration.
  - **`S7.Core.Commands/`**: Contains the implementation of the command pattern, encapsulating all the information needed to perform an action, like installing a stager or dumping memory.
  - **`S7.Infrastructure/`**: Provides concrete implementations of the abstractions defined in `S7.Core.Abstractions`. This includes file repositories and factories.
  - **`S7.Net/`**: Manages the low-level communication with the Siemens PLC, including the implementation of the custom bootloader protocol.
  - **`S7.Services/`**: Contains the core business logic, orchestrating operations by consuming services and repositories defined in the abstraction layer.
  - **`S7.Utils/`**: A shared library for utilities that are used across multiple projects, such as the dump file comparer.
- **`src/S7_Csharp_Utility/`**: The presentation layer, an Avalonia desktop application.
  - **`ViewModels/`**: Contains the view models, which manage the state and logic of the UI, following the MVVM design pattern.
  - **`Views/`**: Contains the Avalonia UI files (`.axaml`) that define the user interface.
  - **`Services/`**: Contains services that are specific to the UI, such as dialog management, logging, and state management.
- **`scripts/`**: Contains utility scripts for development, such as finding `async void` methods or validating `ConfigureAwait` usage to maintain code quality.
- **`tests/`**: Contains unit and integration tests for the projects, mirroring the source code's structure.

### 4. File Placement Patterns

- **Configuration Files**: `config.json` is used for application settings and is located in the output directory.
- **Model/Entity Definitions**: Domain models are defined within the relevant projects. For example, UI-specific models are in `S7_Csharp_Utility/Models`, while core entities would reside in a `Models` folder within a core project.
- **Business Logic**: Service implementations are in `S7.Services`, while command logic is in `S7.Core.Commands`.
- **Interface Definitions**: All interfaces are defined in the `S7.Core.Abstractions` project to enforce the dependency inversion principle.
- **Test Files**: Located in the `tests/` directory, with a separate test project for each project being tested.

### 5. Naming and Organization Conventions

- **File Naming**: `PascalCase` (e.g., `PlcOperationService.cs`).
- **Folder Naming**: `PascalCase`, matching the C# namespaces.
- **Namespace Patterns**: Namespaces map directly to the folder structure (e.g., the `S7_Csharp_Core/Services` directory corresponds to the `S7_Csharp_Core.Services` namespace).
- **Class Naming**: `PascalCase` (e.g., `MainWindowViewModel`).
- **Interface Naming**: `PascalCase` with an `I` prefix (e.g., `IPlcOperationService`).
- **Method Naming**: `PascalCase` (e.g., `DumpMemoryAsync`).
- **Private Fields**: `camelCase` with a leading underscore (e.g., `_plcClient`).

### 6. Navigation and Development Workflow

- **Entry Points**: The application's entry point is `Program.cs` in the `S7_Csharp_Utility` project, where the dependency injection container is configured and the main window is created.
- **Common Development Tasks**:
  - **Adding a New Feature**: Follow the layered architecture: define abstractions, implement core logic in services, and build the UI in the utility project. Register new services in `Program.cs`.
  - **Adding New Tests**: Add a new test class to the appropriate test project in the `tests/` directory.

### 7. Build and Output Organization

- **Build Configuration**: The project is built using the .NET SDK. The build process is defined by the `.csproj` files.
- **Build Command**: `dotnet build src/S7_Csharp_Utility/S7_Csharp_Utility.csproj --configuration Release`
- **Output Structure**: The compiled application is located in `src/S7_Csharp_Utility/bin/Release/net8.0/`.

### 8. .NET-Specific Organization

- **Solution Structure**: A multi-project solution (`.sln`) is used to manage the projects and their dependencies.
- **Project Dependencies**: The `S7_Csharp_Utility` project references the core projects, enforcing a one-way dependency flow from the UI to the core logic.
- **Package Management**: Dependencies are managed via NuGet packages, which are declared in the `.csproj` files.

### 9. Extension and Evolution

- **Extension Points**: The architecture is extensible via its interfaces. New communication channels (`ICommunicationChannel`) or power controllers (`IPowerController`) can be added by creating new implementations of these interfaces.
- **Refactoring Patterns**: The separation of concerns allows layers to be refactored or replaced with minimal impact on other parts of the system.

### 10. Structure Templates

- **New Service Template**:
  1. Define `INewService.cs` in `S7.Core.Abstractions/Services/`.
  2. Implement `NewService.cs` in `S7.Services/`.
  3. Register the service in `Program.cs` in the `S7_Csharp_Utility` project.
- **New Component Template**:
  1. Create a `NewViewModel.cs` in `S7_Csharp_Utility/ViewModels/`.
  2. Create a `NewView.axaml` in `S7_Csharp_Utility/Views/`.
  3. Connect the view and view model using the `ViewLocator`.

### 11. Structure Enforcement

- **Build Checks**: The .NET compiler enforces dependency rules defined by the project references.
- **Code Analysis**: The scripts in the `scripts/` directory can be used to check for common coding issues.
- **Documentation**: This document should be updated whenever significant changes are made to the project's structure.