# MainWindowViewModel Refactoring Implementation Details

**Related Plan**: 20250126-mainwindowviewmodel-refactoring-plan.md
**Created**: 2025-01-26

## Phase 1: Foundation Setup

### Task 1.1: Create FeatureViewModelBase abstract class

**Location**: `src/S7_Csharp_Utility/ViewModels/FeatureViewModelBase.cs`

**Implementation Requirements**:
- Create abstract base class that extends ViewModelBase
- Include common dependencies: ILogger, IApplicationStateService
- Provide protected methods for operation state management
- Include standard error handling patterns
- Follow existing project naming conventions

**Key Features**:
```csharp
public abstract class FeatureViewModelBase : ViewModelBase
{
    protected readonly ILogger Logger;
    protected readonly IApplicationStateService ApplicationStateService;
    
    protected FeatureViewModelBase(ILogger logger, IApplicationStateService applicationStateService)
    
    protected virtual void NotifyOperationStarted(string operationName)
    protected virtual void NotifyOperationCompleted(string operationName)
    protected virtual void HandleException(Exception ex, string context)
}
```

### Task 1.2: Create IApplicationStateService interface and implementation

**Interface Location**: `src/S7_Csharp_Utility/Interfaces/IApplicationStateService.cs`
**Implementation Location**: `src/S7_Csharp_Utility/Services/ApplicationStateService.cs`

**Implementation Requirements**:
- Track global application state across features
- Provide methods to check if operations can be executed
- Implement event notifications for state changes
- Thread-safe implementation for UI updates
- Integration with existing logging patterns

**Key Interface**:
```csharp
public interface IApplicationStateService
{
    bool IsAnyOperationInProgress { get; }
    bool CanExecuteExploitSequence { get; }
    bool CanExecuteMemoryDump { get; }
    
    event EventHandler<ApplicationStateChangedEventArgs> StateChanged;
    
    void NotifyOperationStarted(string operationName);
    void NotifyOperationCompleted(string operationName);
    void RegisterStateProvider(string key, Func<bool> stateProvider);
    void UnregisterStateProvider(string key);
}
```

### Task 1.3: Create IValidationCoordinatorService interface and implementation

**Interface Location**: `src/S7_Csharp_Utility/Interfaces/IValidationCoordinatorService.cs`
**Implementation Location**: `src/S7_Csharp_Utility/Services/ValidationCoordinatorService.cs`

**Implementation Requirements**:
- Coordinate validation across multiple ViewModels
- Aggregate validation errors into summary
- Provide centralized validation state management
- Thread-safe for UI binding updates
- Integration with existing INotifyDataErrorInfo pattern

**Key Interface**:
```csharp
public interface IValidationCoordinatorService
{
    bool HasValidationErrors { get; }
    string ValidationSummary { get; }
    
    event EventHandler<ValidationStateChangedEventArgs> ValidationStateChanged;
    
    void RegisterValidator(string key, INotifyDataErrorInfo validator);
    void UnregisterValidator(string key);
    void RefreshValidationState();
}
```

### Task 1.4: Update dependency injection registrations for new services

**Location**: `src/S7_Csharp_Utility/Program.cs` or DI configuration file

**Implementation Requirements**:
- Register IApplicationStateService as singleton
- Register IValidationCoordinatorService as singleton
- Ensure proper service lifetime management
- Follow existing DI patterns in the project

## Phase 2: Extract Memory Dump Feature

### Task 2.1: Create MemoryDumpFeatureViewModel class

**Location**: `src/S7_Csharp_Utility/ViewModels/Features/MemoryDumpFeatureViewModel.cs`

**Implementation Requirements**:
- Extend FeatureViewModelBase
- Include all memory dump related properties and validation
- Implement memory dump commands
- Handle progress reporting and cancellation
- Integration with IMemoryDumpService

**Properties to Extract**:
- DumpAddress (with validation)
- DumpLength (with validation)
- IsDumpingMemory
- DumpProgressPercentage, DumpProgressBytes, DumpProgressTime, DumpProgressSpeed
- _dumpCancellationTokenSource

**Commands to Extract**:
- DumpMemoryCommand
- CancelDumpCommand

### Task 2.2: Move memory dump properties from MainWindowViewModel

**Implementation Requirements**:
- Move all dump-related properties to MemoryDumpFeatureViewModel
- Maintain existing validation attributes and logic
- Ensure property change notifications work correctly
- Preserve existing validation patterns

### Task 2.3: Move memory dump commands and logic from MainWindowViewModel

**Implementation Requirements**:
- Move DumpMemoryAsync method to MemoryDumpFeatureViewModel
- Move CancelDump method to MemoryDumpFeatureViewModel
- Move progress reporting logic (FormatBytes, FormatTime methods)
- Maintain existing error handling and logging patterns
- Ensure cancellation token handling works correctly

### Task 2.4: Update MainWindowViewModel to use MemoryDumpFeatureViewModel

**Implementation Requirements**:
- Add MemoryDumpFeatureViewModel as constructor dependency
- Expose as public property for view binding
- Remove extracted properties and methods
- Update constructor to include new dependency

### Task 2.5: Update view bindings for memory dump functionality

**Location**: `src/S7_Csharp_Utility/MainWindow.axaml`

**Implementation Requirements**:
- Update all memory dump related bindings to use MemoryDumpFeature property
- Ensure command bindings work correctly
- Maintain existing UI behavior and validation display
- Test all memory dump UI functionality

## Phase 3: Extract Exploit Sequence Feature

### Task 3.1: Create ExploitSequenceFeatureViewModel class

**Location**: `src/S7_Csharp_Utility/ViewModels/Features/ExploitSequenceFeatureViewModel.cs`

**Implementation Requirements**:
- Extend FeatureViewModelBase
- Include exploit sequence state management
- Implement exploit sequence commands
- Integration with IPlcOperationService and IStagerService

**Properties to Extract**:
- IsUploadingStager
- StagerInstalled

**Commands to Extract**:
- StartExploitSequenceCommand

### Task 3.2: Move exploit sequence properties from MainWindowViewModel

**Implementation Requirements**:
- Move IsUploadingStager and StagerInstalled properties
- Maintain property change notifications
- Ensure command CanExecute logic updates correctly

### Task 3.3: Move exploit sequence commands and logic from MainWindowViewModel

**Implementation Requirements**:
- Move StartExploitSequenceAsync method
- Move CanExecuteExploitSequence logic
- Move CreateChannelConfig method (or make it shared)
- Maintain existing error handling and logging
- Ensure integration with power supply and PLC connection ViewModels

### Task 3.4: Update MainWindowViewModel to use ExploitSequenceFeatureViewModel

**Implementation Requirements**:
- Add ExploitSequenceFeatureViewModel as constructor dependency
- Expose as public property for view binding
- Remove extracted properties and methods
- Update constructor to include new dependency

### Task 3.5: Update view bindings for exploit sequence functionality

**Location**: `src/S7_Csharp_Utility/MainWindow.axaml`

**Implementation Requirements**:
- Update exploit sequence related bindings
- Ensure command bindings work correctly
- Maintain existing UI behavior

## Phase 4: Extract Payload Discovery Feature

### Task 4.1: Create PayloadDiscoveryFeatureViewModel class

**Location**: `src/S7_Csharp_Utility/ViewModels/Features/PayloadDiscoveryFeatureViewModel.cs`

**Implementation Requirements**:
- Extend FeatureViewModelBase
- Include payload scanning and discovery functionality
- Implement payload scanning commands
- Integration with IPayloadService

**Properties to Extract**:
- DiscoveredPayloads (ObservableCollection<PayloadInfo>)
- IsScanning
- _scanCancellationTokenSource

**Commands to Extract**:
- CancelScanCommand

### Task 4.2: Move payload discovery properties from MainWindowViewModel

**Implementation Requirements**:
- Move DiscoveredPayloads collection
- Move IsScanning property
- Move _scanCancellationTokenSource field
- Maintain collection change notifications

### Task 4.3: Move payload scanning commands and logic from MainWindowViewModel

**Implementation Requirements**:
- Move ScanPayloadsAsync method
- Move StartScanPayloads method
- Move CancelScan method
- Maintain existing error handling and progress reporting
- Ensure thread-safe UI updates

### Task 4.4: Update MainWindowViewModel to use PayloadDiscoveryFeatureViewModel

**Implementation Requirements**:
- Add PayloadDiscoveryFeatureViewModel as constructor dependency
- Expose as public property for view binding
- Remove extracted properties and methods
- Update constructor to include new dependency

### Task 4.5: Update view bindings for payload discovery functionality

**Location**: `src/S7_Csharp_Utility/MainWindow.axaml`

**Implementation Requirements**:
- Update payload discovery related bindings
- Ensure collection bindings work correctly
- Maintain existing UI behavior for payload list

## Phase 5: Extract Profile Management Feature

### Task 5.1: Create ProfileManagementFeatureViewModel class

**Location**: `src/S7_Csharp_Utility/ViewModels/Features/ProfileManagementFeatureViewModel.cs`

**Implementation Requirements**:
- Extend FeatureViewModelBase
- Include device profile management functionality
- Implement profile loading and management commands
- Integration with ConfigurationService

**Properties to Extract**:
- LoadedProfile
- MemoryRegions
- SelectedMemoryRegion

**Commands to Extract**:
- LoadProfileCommand
- ShowProfileManagementCommand

### Task 5.2: Move profile management properties from MainWindowViewModel

**Implementation Requirements**:
- Move LoadedProfile property
- Move MemoryRegions property
- Move SelectedMemoryRegion property
- Maintain property change notifications and region selection logic

### Task 5.3: Move profile management commands and logic from MainWindowViewModel

**Implementation Requirements**:
- Move LoadProfileAsync method
- Move ShowProfileManagement method
- Maintain existing error handling and dialog integration
- Ensure profile loading updates memory regions correctly

### Task 5.4: Update MainWindowViewModel to use ProfileManagementFeatureViewModel

**Implementation Requirements**:
- Add ProfileManagementFeatureViewModel as constructor dependency
- Expose as public property for view binding
- Remove extracted properties and methods
- Update constructor to include new dependency

### Task 5.5: Update view bindings for profile management functionality

**Location**: `src/S7_Csharp_Utility/MainWindow.axaml`

**Implementation Requirements**:
- Update profile management related bindings
- Ensure memory region selection works correctly
- Maintain existing UI behavior for profile loading

## Phase 6: Finalize MainWindowViewModel Refactoring

### Task 6.1: Remove extracted code from MainWindowViewModel

**Implementation Requirements**:
- Remove all properties that have been moved to feature ViewModels
- Remove all methods that have been moved to feature ViewModels
- Remove unused fields and cancellation tokens
- Clean up unused using statements

### Task 6.2: Implement orchestration logic in MainWindowViewModel

**Implementation Requirements**:
- Implement coordination between feature ViewModels
- Handle cross-feature communication through events or services
- Maintain global command coordination where needed
- Ensure proper initialization of feature ViewModels

### Task 6.3: Update constructor and reduce dependencies

**Implementation Requirements**:
- Replace individual service dependencies with feature ViewModels
- Reduce constructor parameter count to ≤8
- Maintain existing child ViewModels (PlcConnectionViewModel, etc.)
- Update constructor documentation

### Task 6.4: Update configuration management to work with new structure

**Implementation Requirements**:
- Update LoadConfigurationOnStartup to work with feature ViewModels
- Update SaveConfigurationOnExit to work with feature ViewModels
- Update LoadConfigurationAsync to work with feature ViewModels
- Ensure configuration persistence works correctly

### Task 6.5: Update global command coordination

**Implementation Requirements**:
- Update remaining global commands (SaveConfigurationCommand, etc.)
- Ensure proper command coordination between features
- Maintain existing command patterns and error handling

## Phase 7: Integration and Testing

### Task 7.1: Update dependency injection container configuration

**Location**: `src/S7_Csharp_Utility/Program.cs`

**Implementation Requirements**:
- Register all new feature ViewModels with appropriate lifetimes
- Register new services (ApplicationStateService, ValidationCoordinatorService)
- Ensure proper dependency resolution order
- Follow existing DI patterns in the project

### Task 7.2: Update MainWindow.axaml bindings for new ViewModel structure

**Location**: `src/S7_Csharp_Utility/MainWindow.axaml`

**Implementation Requirements**:
- Update all bindings to use nested feature ViewModels
- Ensure command bindings work correctly
- Maintain existing UI layout and behavior
- Test all UI interactions work correctly

### Task 7.3: Test all functionality works correctly

**Implementation Requirements**:
- Test memory dump functionality end-to-end
- Test exploit sequence functionality end-to-end
- Test payload discovery functionality end-to-end
- Test profile management functionality end-to-end
- Test configuration save/load functionality
- Verify all UI interactions work as expected

### Task 7.4: Update existing unit tests for new structure

**Location**: `tests/S7_Csharp_Utility.Tests/ViewModels/`

**Implementation Requirements**:
- Update MainWindowViewModelTests for new structure
- Ensure existing test coverage is maintained
- Update test mocks and setup for new dependencies
- Verify all tests pass with new structure

### Task 7.5: Add unit tests for new feature ViewModels

**Location**: `tests/S7_Csharp_Utility.Tests/ViewModels/Features/`

**Implementation Requirements**:
- Create unit tests for MemoryDumpFeatureViewModel
- Create unit tests for ExploitSequenceFeatureViewModel
- Create unit tests for PayloadDiscoveryFeatureViewModel
- Create unit tests for ProfileManagementFeatureViewModel
- Create unit tests for ApplicationStateService
- Create unit tests for ValidationCoordinatorService
- Follow existing test patterns and conventions

## Phase 8: Documentation and Cleanup

### Task 8.1: Update XML documentation for all new classes

**Implementation Requirements**:
- Add comprehensive XML documentation to all new classes
- Include parameter descriptions and return value documentation
- Add example usage where appropriate
- Follow existing documentation patterns in the project

### Task 8.2: Update architecture documentation

**Location**: Documentation files or README

**Implementation Requirements**:
- Document the new ViewModel architecture
- Explain the feature ViewModel pattern
- Document the state management services
- Update any architectural diagrams if they exist

### Task 8.3: Clean up any unused code or imports

**Implementation Requirements**:
- Remove any unused using statements
- Remove any unused private methods or fields
- Clean up any commented-out code
- Ensure consistent code formatting

### Task 8.4: Verify all code follows project conventions

**Implementation Requirements**:
- Verify naming conventions are followed
- Ensure consistent code style and formatting
- Verify proper use of async/await patterns
- Ensure proper error handling patterns are used

### Task 8.5: Final integration testing and validation

**Implementation Requirements**:
- Perform comprehensive end-to-end testing
- Verify all success criteria are met
- Ensure no regressions in existing functionality
- Validate performance is not negatively impacted
- Confirm all UI interactions work correctly

## Common Patterns and Conventions

### Error Handling Pattern
```csharp
try
{
    // Operation logic
}
catch (OperationCanceledException)
{
    Logger.LogInformation("Operation was cancelled by user");
    // Handle cancellation
}
catch (Exception ex)
{
    Logger.LogError(ex, "Error during operation");
    HandleException(ex, "Operation context");
}
```

### Progress Reporting Pattern
```csharp
var progress = new Progress<ProgressType>(progressInfo =>
{
    Dispatcher.UIThread.InvokeAsync(() =>
    {
        // Update UI properties
    });
});
```

### Command Implementation Pattern
```csharp
public ICommand CommandName { get; }

// In constructor:
CommandName = new AsyncRelayCommand(ExecuteCommandAsync, CanExecuteCommand);

private bool CanExecuteCommand() => !IsOperationInProgress;

private async Task ExecuteCommandAsync()
{
    // Implementation
}
```

### Validation Pattern
```csharp
[Required(ErrorMessage = "Field is required")]
[RegularExpression(@"pattern", ErrorMessage = "Invalid format")]
public string PropertyName
{
    get => _propertyName;
    set 
    { 
        if (SetProperty(ref _propertyName, value))
        {
            ValidateProperty(value, nameof(PropertyName));
        }
    }
}
```