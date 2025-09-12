### 📘 Project Best Practices

#### 1. Project Purpose
This project is a cross-platform desktop utility for interacting with Siemens S7 PLCs. Its primary purpose is to provide a graphical interface for advanced operations, including uploading custom payloads (stagers), dumping memory regions, comparing firmware/memory dumps, and controlling PLC power via a Modbus-enabled power supply. The tool is designed for security researchers and engineers working with Siemens S7 hardware.

#### 2. Project Structure
The solution is organized into two main parts: a core library for PLC communication and a desktop application.
- **`src/Core/`**: Contains the low-level libraries for handling PLC communication.
  - **`S7.Net/`**: The core library for the S7 communication protocol.
  - **`S7.Utils/`**: Helper utilities, such as the `DumpComparer` for analyzing memory dumps.
- **`src/S7_Csharp_Utility/`**: The main Avalonia-based desktop application.
  - **`ViewModels/`**: Contains view models that follow the MVVM pattern, holding the application's state and business logic.
  - **`Services/`**: Contains services that encapsulate specific functionalities, such as logging, configuration management, and process control (e.g., `SocatService`).
  - **`Models/`**: Defines the data structures used in the application, like `ApplicationConfiguration`.
  - **`Views/`**: Although not an explicit folder, the `.axaml` files define the UI (the "Views" in MVVM).
  - **`Commands/`**: Holds the `RelayCommand` implementation for the MVVM pattern.
  - **`Interfaces/`**: Defines abstractions, such as `IDialogService`, to decouple ViewModels from the View.

#### 3. Test Strategy
Currently, the project does not have an established test suite. If tests were to be added, they should follow these guidelines:
- **Framework**: Use a standard .NET testing framework like xUnit or NUnit.
- **Organization**: Create a separate test project for each project in the solution (e.g., `S7.Net.Tests`, `S7_Csharp_Utility.Tests`).
- **Unit Tests**: Focus on testing individual methods in services and view models. Use mocking (e.g., with Moq or NSubstitute) to isolate dependencies like `IDialogService` or communication channels.
- **Integration Tests**: Write integration tests for end-to-end workflows, such as the full memory dump sequence, but be mindful of the hardware dependency.

#### 4. Code Style
- **MVVM Pattern**: Strictly adhere to the Model-View-ViewModel (MVVM) pattern. Business logic should reside in ViewModels, and UI-specific interactions should be handled in the `.axaml.cs` code-behind only when necessary (e.g., for complex UI control interactions that are difficult to express in pure MVVM).
- **Asynchronous Operations**: Use `async`/`await` for all I/O-bound operations, including file access, network communication, and process management. Command handlers should be `async Task` rather than `async void`.
- **Naming Conventions**:
  - **Classes and Properties**: `PascalCase` (e.g., `MainWindowViewModel`, `PlcHost`).
  - **Private Fields**: `_camelCase` (e.g., `_powerController`).
  - **Methods**: `PascalCase` (e.g., `UploadStager`). Asynchronous methods should end with the `Async` suffix (e.g., `StartSocatAsync`).
- **Error Handling**: Use `try-catch` blocks to handle exceptions in service and view model methods. Log errors using the `LoggingService` and display user-friendly messages via the `IDialogService`.

#### 5. Common Patterns
- **Dependency Injection**: Services are manually injected into the `MainWindowViewModel`'s constructor. This pattern should be maintained to keep the code decoupled and testable.
- **Service Abstraction**: Use services to encapsulate distinct responsibilities (e.g., `SocatService`, `ConfigurationService`, `PowerController`).
- **`IDialogService`**: To maintain separation of concerns, all file/dialog interactions from the ViewModel must go through the `IDialogService` interface.
- **`RelayCommand`**: Use `RelayCommand` for implementing the `ICommand` interface in ViewModels. The `CanExecute` delegate should be used to enable/disable UI elements based on the application's state.

#### 6. Do's and Don'ts
- ✅ **Do** use `async Task` for command logic to prevent unhandled exceptions.
- ✅ **Do** use the `LoggingService` for all diagnostic messages.
- ✅ **Do** abstract any new platform-specific UI interaction behind an interface (like `IDialogService`).
- ❌ **Don't** put business logic in the `.axaml.cs` code-behind. Keep it in the ViewModel.
- ❌ **Don't** use `async void` except for top-level event handlers that cannot be `async Task`.
- ❌ **Don't** hardcode strings like file paths or configuration keys; define them as constants or in a configuration model.

#### 7. Tools & Dependencies
- **.NET 8**: The core framework for the entire application.
- **Avalonia**: The cross-platform UI framework used for the desktop application.
- **S7.Net**: The internal library for handling the Siemens S7 communication protocol.

#### 8. Other Notes
- When adding new features, first consider if the logic belongs in an existing service or if a new service is required.
- Any new UI element that triggers an action should be bound to an `ICommand` in the ViewModel.
- Be mindful of the application's state (`IsUploadingStager`, `IsDumpingMemory`, etc.) when implementing new commands to prevent concurrent, conflicting operations.
