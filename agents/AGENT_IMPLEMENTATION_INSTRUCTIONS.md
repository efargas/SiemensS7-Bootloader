# Agent Implementation Instructions

## 🎯 Mission Statement
Transform the SiemensS7-Bootloader project into a fully compliant enterprise-grade .NET application implementing all required design patterns while maintaining 100% backward compatibility and functionality.

## 📋 Pre-Implementation Checklist

### Environment Validation
```bash
# Verify .NET 8.0 SDK
dotnet --version  # Must be 8.0.x

# Verify all projects build
dotnet build src/SiemensS7-Bootloader.sln

# Verify all tests pass
dotnet test tests/S7.Core.Tests/S7.Core.Tests.csproj
dotnet test tests/S7_Csharp_Utility.Tests/S7_Csharp_Utility.Tests.csproj

# Create implementation branch
git checkout -b feature/design-pattern-implementation
git tag backup-before-implementation
```

## 🚨 CRITICAL CONSTRAINTS

### NEVER MODIFY (Protected Elements):
- `src/S7_Csharp_Core/S7.Net/PlcClient.cs` - Core PLC communication
- `src/S7_Csharp_Core/S7.Net/PlcProtocol.cs` - Protocol implementation
- `src/S7_Csharp_Core/S7.Net/PlcMemoryManager.cs` - Memory management
- `src/S7_Csharp_Utility/Resources/*.resx` - Existing resource files
- Any existing public API method signatures
- Database schemas or data structures
- Configuration file formats (maintain backward compatibility)

### ALWAYS PRESERVE:
- All existing functionality
- All existing tests (they must continue to pass)
- Public API contracts
- Configuration compatibility
- Resource file structure

## 📊 Implementation Phases

### Phase 1: Command Pattern Completion (Days 1-3)

#### 1.1 Create Command Handler Base Classes
**Priority**: CRITICAL
**Risk**: LOW

**Files to Create**:
```
src/S7_Csharp_Core/S7.Core.Abstractions/Commands/CommandHandlerOptions.cs
src/S7_Csharp_Core/S7.Core.Abstractions/Commands/CommandHandlerBase.cs
src/S7_Csharp_Core/S7.Core.Abstractions/Commands/ICommandSetup.cs
```

**Implementation Steps**:
1. Create `CommandHandlerOptions` base class with required properties
2. Implement generic `CommandHandler<TOptions>` base class
3. Add static `SetupCommand(IHost host)` method interface
4. Create validation framework integration
5. Add comprehensive logging and error handling

**Validation Criteria**:
- [ ] All new command handlers inherit from base class
- [ ] Static setup methods implemented for all handlers
- [ ] Validation framework integrated
- [ ] Existing handlers continue to work unchanged
- [ ] All tests pass

#### 1.2 Refactor Existing Command Handlers
**Files to Modify**:
```
src/S7_Csharp_Core/S7.Core.Commands/Handlers/MemoryDumpCommandHandler.cs
src/S7_Csharp_Core/S7.Core.Commands/Handlers/StagerInstallCommandHandler.cs
```

**Implementation Steps**:
1. Create options classes inheriting from `CommandHandlerOptions`
2. Refactor handlers to inherit from `CommandHandler<TOptions>`
3. Implement static setup methods
4. Add comprehensive validation
5. Maintain existing public API

### Phase 2: UI Architecture Refactoring (Days 4-8)

#### 2.1 Extract Business Logic Services
**Priority**: CRITICAL
**Risk**: HIGH

**Files to Create**:
```
src/S7_Csharp_Core/S7.Core.Abstractions/Services/IPlcOperationService.cs
src/S7_Csharp_Core/S7.Core.Abstractions/Services/IMemoryDumpService.cs
src/S7_Csharp_Core/S7.Core.Abstractions/Services/IStagerService.cs
src/S7_Csharp_Core/S7.Services/PlcOperationService.cs
src/S7_Csharp_Core/S7.Services/MemoryDumpService.cs
src/S7_Csharp_Core/S7.Services/StagerService.cs
```

**Implementation Steps**:
1. Define service interfaces with comprehensive contracts
2. Extract business logic from ViewModels into services
3. Implement proper dependency injection
4. Add comprehensive error handling and logging
5. Ensure thread-safe operations

**Files to Refactor**:
```
src/S7_Csharp_Utility/ViewModels/MainWindowViewModel.cs
src/S7_Csharp_Utility/ViewModels/PlcConnectionViewModel.cs
src/S7_Csharp_Utility/ViewModels/ModbusPowerSupplyViewModel.cs
```

**Refactoring Rules**:
- ViewModels ONLY handle UI state and user interactions
- NO direct PLC communication in ViewModels
- NO file I/O operations in ViewModels
- ALL business logic moved to service layer
- Proper async/await patterns with UI thread marshalling

#### 2.2 Fix Thread Safety Issues
**Priority**: CRITICAL
**Risk**: MEDIUM

**Implementation Steps**:
1. Identify all UI collection modifications
2. Implement proper `Dispatcher.UIThread.InvokeAsync()` usage
3. Add thread-safe collection wrappers where needed
4. Implement proper cancellation token handling
5. Add comprehensive testing for thread safety

### Phase 3: Primary Constructor Implementation (Days 9-11)

#### 3.1 Convert All Classes to Primary Constructors
**Priority**: HIGH
**Risk**: LOW

**Target Files**: All classes with traditional constructors (~50 files)

**Implementation Pattern**:
```csharp
// BEFORE
public class ExampleService
{
    private readonly ILogger<ExampleService> _logger;
    private readonly IConfiguration _config;

    public ExampleService(ILogger<ExampleService> logger, IConfiguration config)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }
}

// AFTER
public class ExampleService(
    ILogger<ExampleService> logger,
    IConfiguration config)
{
    private readonly ILogger<ExampleService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly IConfiguration _config = config ?? throw new ArgumentNullException(nameof(config));
}
```

**Validation Criteria**:
- [ ] All new classes use primary constructors
- [ ] Null checks preserved
- [ ] Dependency injection continues to work
- [ ] All tests pass
- [ ] No breaking changes to public APIs

### Phase 4: Enhanced Validation & Configuration (Days 12-15)

#### 4.1 Implement Data Annotations Validation
**Files to Create/Modify**:
```
src/S7_Csharp_Core/S7.Core.Abstractions/Validation/ValidationAttributes.cs
src/S7_Csharp_Core/S7.Core.Abstractions/Configuration/ConfigurationOptions.cs
```

**Implementation Steps**:
1. Create custom validation attributes
2. Add data annotations to all command options
3. Implement configuration validation
4. Add validation middleware/services
5. Integrate with existing error handling

#### 4.2 Strongly-Typed Configuration
**Implementation Steps**:
1. Create strongly-typed configuration classes
2. Add validation attributes
3. Implement configuration validation on startup
4. Add configuration change detection
5. Maintain backward compatibility

### Phase 5: Testing & Quality Assurance (Days 16-20)

#### 5.1 Expand Test Coverage
**Files to Create**:
```
tests/S7.Integration.Tests/S7.Integration.Tests.csproj
tests/S7.UI.Tests/S7.UI.Tests.csproj
tests/S7_Csharp_Utility.Tests/ViewModels/MainWindowViewModelTests.cs
tests/S7_Csharp_Utility.Tests/Services/PlcOperationServiceTests.cs
```

**Testing Requirements**:
- Unit tests for all new services
- Integration tests for command handlers
- UI tests for ViewModels (without business logic)
- Performance tests for critical paths
- Thread safety tests

#### 5.2 Quality Gates Implementation
**Metrics to Achieve**:
- Code coverage >80%
- Cyclomatic complexity <10 per method
- Code duplication <5%
- No critical security vulnerabilities
- Performance within 10% of baseline

## 🔧 Implementation Guidelines

### Code Style Standards
```csharp
// Use primary constructors for all new classes
public class NewService(ILogger<NewService> logger) : INewService
{
    private readonly ILogger<NewService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
}

// Use proper async/await patterns
public async Task<Result> ProcessAsync(CancellationToken cancellationToken = default)
{
    try
    {
        var result = await SomeOperationAsync(cancellationToken).ConfigureAwait(false);
        return Result.Success(result);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Operation failed");
        return Result.Failure(ex.Message);
    }
}

// Use proper validation
public class CommandOptions : CommandHandlerOptions
{
    [Required(ErrorMessage = "Address is required")]
    [RegularExpression(@"^0x[0-9a-fA-F]{1,8}$", ErrorMessage = "Invalid hex address")]
    public string Address { get; set; } = string.Empty;
}
```

### Error Handling Standards
```csharp
// Always use structured logging
_logger.LogInformation("Operation started with {ParameterCount} parameters", parameters.Count);

// Always handle exceptions gracefully
try
{
    await RiskyOperationAsync();
}
catch (SpecificException ex)
{
    _logger.LogWarning(ex, "Specific error occurred, continuing with fallback");
    await FallbackOperationAsync();
}
catch (Exception ex)
{
    _logger.LogError(ex, "Unexpected error in operation");
    throw; // Re-throw if cannot handle
}
```

### Testing Standards
```csharp
[Fact]
public async Task ServiceMethod_ValidInput_ReturnsExpectedResult()
{
    // Arrange
    var mockDependency = new Mock<IDependency>();
    mockDependency.Setup(x => x.MethodAsync(It.IsAny<string>()))
              .ReturnsAsync("expected");
    var service = new Service(mockDependency.Object);

    // Act
    var result = await service.ProcessAsync("input");

    // Assert
    Assert.True(result.IsSuccess);
    Assert.Equal("expected", result.Value);
    mockDependency.Verify(x => x.MethodAsync("input"), Times.Once);
}
```

## 📊 Progress Tracking

### Daily Checklist Template
```markdown
## Day X Progress Report

### Completed Tasks:
- [ ] Task 1 description
- [ ] Task 2 description

### Current Status:
- Files modified: X
- Tests added: X
- Tests passing: X/X
- Code coverage: X%

### Issues Encountered:
- Issue 1 and resolution
- Issue 2 and resolution

### Next Day Plan:
- Task 1
- Task 2
```

### Quality Gates Checklist
```markdown
## Phase X Quality Gate

### Code Quality:
- [ ] All tests pass (100%)
- [ ] Code coverage >80%
- [ ] No critical security issues
- [ ] Performance within acceptable range
- [ ] All public APIs documented

### Pattern Implementation:
- [ ] Command pattern fully implemented
- [ ] UI/Business logic separated
- [ ] Primary constructors adopted
- [ ] Validation framework integrated
- [ ] Thread safety ensured

### Compatibility:
- [ ] All existing functionality preserved
- [ ] No breaking API changes
- [ ] Configuration backward compatible
- [ ] Resource files intact
```

## 🚀 Success Criteria

### Technical Success Metrics:
1. **100% Test Pass Rate**: All existing and new tests must pass
2. **Zero Breaking Changes**: All existing public APIs preserved
3. **Pattern Compliance**: All required design patterns fully implemented
4. **Performance Maintained**: No >10% performance regression
5. **Security Enhanced**: No new security vulnerabilities introduced

### Quality Success Metrics:
1. **Code Coverage**: >80% overall, >90% for new code
2. **Documentation**: 100% public API documentation
3. **Maintainability**: Cyclomatic complexity <10 per method
4. **Reliability**: Zero critical bugs in implementation
5. **Usability**: All existing features work identically

## 🔄 Continuous Validation Protocol

### After Each Commit:
```bash
# Run quick validation
dotnet build src/SiemensS7-Bootloader.sln
dotnet test tests/S7.Core.Tests/S7.Core.Tests.csproj --verbosity minimal

# Check code quality
dotnet format --verify-no-changes
```

### After Each Phase:
```bash
# Full test suite
dotnet test --collect:"XPlat Code Coverage"

# Performance benchmarks
dotnet run --project benchmarks/S7.Benchmarks

# Security scan
dotnet list package --vulnerable
```

### Before Final Submission:
```bash
# Complete validation suite
./scripts/validate-complete-implementation.sh

# Generate final report
./scripts/generate-implementation-report.sh
```

## 📞 Escalation Protocol

### When to Escalate:
1. **Breaking Changes Required**: If implementation requires breaking existing APIs
2. **Performance Issues**: If >10% performance regression cannot be avoided
3. **Test Failures**: If existing tests fail and cannot be fixed without breaking changes
4. **Security Concerns**: If implementation introduces security vulnerabilities
5. **Timeline Issues**: If implementation cannot be completed within estimated timeframe

### How to Escalate:
1. Document the specific issue and attempted solutions
2. Provide impact analysis and risk assessment
3. Suggest alternative approaches or compromises
4. Request guidance on priority and approach

This comprehensive implementation plan ensures successful transformation of the SiemensS7-Bootloader project while maintaining all existing functionality and quality standards.