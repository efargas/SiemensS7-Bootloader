# Phase 2: Command Pattern Restoration - Detailed Implementation Plan

## Overview
Phase 2 focuses on restoring the command pattern functionality that was temporarily removed during Phase 1 to resolve circular dependencies. This phase will implement a clean, dependency-free command architecture.

**Duration**: 1 week  
**Priority**: HIGH  
**Dependencies**: Phase 1 completion

## Task 2.1: Command Pattern Architecture Redesign

### 2.1.1 Create Shared Command Interfaces ✅ COMPLETED 2025-01-24
**Estimated Time**: 2 hours  
**Actual Time**: 1.5 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create S7.Core.Abstractions Project** ✅ COMPLETED
   - New project for shared interfaces and abstractions
   - No dependencies on UI or specific implementations
   - Contains command interfaces, result types, and base classes

2. **Define Core Command Interfaces** ✅ COMPLETED
   ```csharp
   public interface ICommand<TResult>
   {
       string CorrelationId { get; }
   }
   
   public interface ICommandHandler<TCommand, TResult> 
       where TCommand : ICommand<TResult>
   {
       Task<CommandResult<TResult>> HandleAsync(TCommand command, CancellationToken cancellationToken = default);
   }
   ```

3. **Create Command Result Types** ✅ COMPLETED
   ```csharp
   public class CommandResult<T>
   {
       public bool IsSuccess { get; init; }
       public T? Data { get; init; }
       public string? ErrorMessage { get; init; }
       public Exception? Exception { get; init; }
       public IReadOnlyList<string> ValidationErrors { get; init; }
       public string? CorrelationId { get; init; }
   }
   ```

4. **Create Validation Infrastructure** ✅ COMPLETED
   - IValidator<T> interface for command validation
   - ValidationResult type for validation outcomes
   - Static factory methods for easy result creation

5. **Create Configuration Types** ✅ COMPLETED
   - CommunicationChannelConfig for TCP/Serial settings
   - PowerControllerConfig for power control operations
   - Immutable objects with data annotation validation

#### Acceptance Criteria:
- [x] S7.Core.Abstractions project created ✅ COMPLETED
- [x] Core interfaces defined without external dependencies ✅ COMPLETED
- [x] Command result types implemented ✅ COMPLETED
- [x] Project compiles without dependencies on UI layer ✅ COMPLETED

### 2.1.2 Implement Memory Dump Command
**Estimated Time**: 3 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create Memory Dump Command**
   ```csharp
   public class MemoryDumpCommand : ICommand<MemoryDumpResult>
   {
       public uint Address { get; init; }
       public uint Length { get; init; }
       public string PayloadPath { get; init; } = string.Empty;
       public string OutputPath { get; init; } = string.Empty;
       public CommunicationChannelConfig ChannelConfig { get; init; }
       public bool OverwriteExisting { get; init; }
       public string? CustomFilename { get; init; }
       public string CorrelationId { get; init; } = Guid.NewGuid().ToString();
   }
   ```

2. **Create Memory Dump Handler**
   ```csharp
   public class MemoryDumpCommandHandler : ICommandHandler<MemoryDumpCommand, MemoryDumpResult>
   {
       private readonly ILogger<MemoryDumpCommandHandler> _logger;
       private readonly PayloadManager _payloadManager;
       
       public async Task<MemoryDumpResult> HandleAsync(MemoryDumpCommand command, CancellationToken cancellationToken)
       {
           // Implementation without circular dependencies
       }
   }
   ```

3. **Add Command Validation**
   ```csharp
   public class MemoryDumpCommandValidator : IValidator<MemoryDumpCommand>
   {
       public ValidationResult Validate(MemoryDumpCommand command)
       {
           // Validation logic
       }
   }
   ```

#### Acceptance Criteria:
- [ ] MemoryDumpCommand implemented with proper validation
- [ ] MemoryDumpCommandHandler handles execution without UI dependencies
- [ ] Command validation separates concerns properly
- [ ] Unit tests cover all scenarios

### 2.1.3 Implement Stager Install Command
**Estimated Time**: 3 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create Stager Install Command**
   ```csharp
   public class StagerInstallCommand : ICommand<StagerInstallResult>
   {
       public string PayloadPath { get; init; } = string.Empty;
       public CommunicationChannelConfig ChannelConfig { get; init; }
       public PowerControllerConfig PowerConfig { get; init; }
       public bool PerformHandshake { get; init; } = true;
       public bool GetVersionInfo { get; init; } = false;
       public string CorrelationId { get; init; } = Guid.NewGuid().ToString();
   }
   ```

2. **Create Stager Install Handler**
   ```csharp
   public class StagerInstallCommandHandler : ICommandHandler<StagerInstallCommand, StagerInstallResult>
   {
       private readonly ILogger<StagerInstallCommandHandler> _logger;
       private readonly PayloadManager _payloadManager;
       private readonly IPowerController _powerController;
       
       public async Task<StagerInstallResult> HandleAsync(StagerInstallCommand command, CancellationToken cancellationToken)
       {
           // Implementation
       }
   }
   ```

#### Acceptance Criteria:
- [ ] StagerInstallCommand implemented with validation
- [ ] StagerInstallCommandHandler works without circular dependencies
- [ ] Power controller integration through interface
- [ ] Comprehensive error handling and logging

## Task 2.2: Command Validation Enhancement

### 2.2.1 Create Custom Validation Attributes ⏳ NEXT
**Estimated Time**: 2 hours  
**Assignee**: Mid-level Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **File Path Validation**
   ```csharp
   [AttributeUsage(AttributeTargets.Property)]
   public class FilePathExistsAttribute : ValidationAttribute
   {
       protected override ValidationResult IsValid(object value, ValidationContext validationContext)
       {
           if (value is string path && !string.IsNullOrEmpty(path))
           {
               return File.Exists(path) ? ValidationResult.Success : 
                   new ValidationResult($"File not found: {path}");
           }
           return new ValidationResult("File path is required");
       }
   }
   ```

2. **Directory Validation**
   ```csharp
   [AttributeUsage(AttributeTargets.Property)]
   public class DirectoryExistsAttribute : ValidationAttribute
   {
       public bool CreateIfMissing { get; set; } = false;
       
       protected override ValidationResult IsValid(object value, ValidationContext validationContext)
       {
           // Implementation
       }
   }
   ```

3. **Network Address Validation**
   ```csharp
   [AttributeUsage(AttributeTargets.Property)]
   public class NetworkAddressAttribute : ValidationAttribute
   {
       protected override ValidationResult IsValid(object value, ValidationContext validationContext)
       {
           // Validate IP address or hostname
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Custom validation attributes created
- [ ] Attributes work with DataAnnotations validation
- [ ] Comprehensive error messages with resource keys
- [ ] Unit tests for all validation scenarios

### 2.2.2 Implement Command Validation Pipeline
**Estimated Time**: 2 hours  
**Assignee**: Mid-level Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **Create Validation Pipeline**
   ```csharp
   public class CommandValidationPipeline<TCommand>
   {
       private readonly IEnumerable<IValidator<TCommand>> _validators;
       
       public ValidationResult ValidateCommand(TCommand command)
       {
           // Run all validators and aggregate results
       }
   }
   ```

2. **Integrate with Command Handlers**
   ```csharp
   public abstract class ValidatedCommandHandler<TCommand, TResult> : ICommandHandler<TCommand, TResult>
       where TCommand : ICommand<TResult>
   {
       protected abstract Task<TResult> ExecuteValidatedAsync(TCommand command, CancellationToken cancellationToken);
       
       public async Task<TResult> HandleAsync(TCommand command, CancellationToken cancellationToken)
       {
           var validationResult = ValidateCommand(command);
           if (!validationResult.IsValid)
           {
               return CreateValidationFailureResult(validationResult);
           }
           
           return await ExecuteValidatedAsync(command, cancellationToken);
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Validation pipeline processes multiple validators
- [ ] Command handlers integrate validation seamlessly
- [ ] Validation errors are properly formatted with resources
- [ ] Performance impact is minimal

## Task 2.3: Power Controller Abstraction

### 2.3.1 Create Power Controller Interface
**Estimated Time**: 1 hour  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Define Power Controller Interface**
   ```csharp
   public interface IPowerController
   {
       Task PowerCycleAsync(PowerControllerConfig config, CancellationToken cancellationToken = default);
       Task SetPowerAsync(PowerControllerConfig config, bool powerOn, CancellationToken cancellationToken = default);
       Task<bool> GetPowerStatusAsync(PowerControllerConfig config, CancellationToken cancellationToken = default);
   }
   ```

2. **Create Configuration Types**
   ```csharp
   public class PowerControllerConfig
   {
       public string Host { get; init; } = string.Empty;
       public int Port { get; init; } = 502;
       public int Coil { get; init; }
       public int DelaySeconds { get; init; } = 5;
       public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
   }
   ```

#### Acceptance Criteria:
- [ ] Interface defined without implementation dependencies
- [ ] Configuration types are immutable and validated
- [ ] Interface supports async operations with cancellation
- [ ] Documentation covers all parameters and behaviors

### 2.3.2 Implement Modbus Power Controller
**Estimated Time**: 2 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create Modbus Implementation**
   ```csharp
   public class ModbusPowerController : IPowerController, IDisposable
   {
       private readonly ILogger<ModbusPowerController> _logger;
       private readonly IModbusMaster _modbusMaster;
       
       public async Task PowerCycleAsync(PowerControllerConfig config, CancellationToken cancellationToken)
       {
           // Implementation using NModbus
       }
   }
   ```

2. **Add Connection Management**
   ```csharp
   public class ModbusConnectionManager : IDisposable
   {
       public async Task<IModbusMaster> GetConnectionAsync(string host, int port, CancellationToken cancellationToken)
       {
           // Connection pooling and management
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Modbus power controller implements interface
- [ ] Connection management handles failures gracefully
- [ ] Proper resource disposal and cleanup
- [ ] Comprehensive logging and error handling

## Task 2.4: Command Registration and DI

### 2.4.1 Create Command Registration Extensions
**Estimated Time**: 1 hour  
**Assignee**: Mid-level Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **Command Handler Registration**
   ```csharp
   public static class CommandServiceExtensions
   {
       public static IServiceCollection AddCommandHandlers(this IServiceCollection services)
       {
           services.AddScoped<ICommandHandler<MemoryDumpCommand, MemoryDumpResult>, MemoryDumpCommandHandler>();
           services.AddScoped<ICommandHandler<StagerInstallCommand, StagerInstallResult>, StagerInstallCommandHandler>();
           
           return services;
       }
       
       public static IServiceCollection AddCommandValidation(this IServiceCollection services)
       {
           services.AddScoped<IValidator<MemoryDumpCommand>, MemoryDumpCommandValidator>();
           services.AddScoped<IValidator<StagerInstallCommand>, StagerInstallCommandValidator>();
           
           return services;
       }
   }
   ```

2. **Power Controller Registration**
   ```csharp
   public static IServiceCollection AddPowerController(this IServiceCollection services)
   {
       services.AddSingleton<IPowerController, ModbusPowerController>();
       services.AddSingleton<ModbusConnectionManager>();
       
       return services;
   }
   ```

#### Acceptance Criteria:
- [ ] Extension methods register all command components
- [ ] Service lifetimes are appropriate for each component
- [ ] Registration is modular and testable
- [ ] Documentation explains registration options

## Task 2.5: Integration and Testing

### 2.5.1 Create Command Integration Tests
**Estimated Time**: 3 hours  
**Assignee**: Mid-level Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **End-to-End Command Tests**
   ```csharp
   public class MemoryDumpCommandIntegrationTests
   {
       [Fact]
       public async Task MemoryDumpCommand_WithValidParameters_ShouldSucceed()
       {
           // Arrange
           var services = CreateTestServices();
           var handler = services.GetRequiredService<ICommandHandler<MemoryDumpCommand, MemoryDumpResult>>();
           
           var command = new MemoryDumpCommand
           {
               Address = 0x1000,
               Length = 1024,
               PayloadPath = "test-payload",
               OutputPath = "test-output"
           };
           
           // Act
           var result = await handler.HandleAsync(command);
           
           // Assert
           result.IsSuccess.Should().BeTrue();
       }
   }
   ```

2. **Validation Integration Tests**
   ```csharp
   public class CommandValidationIntegrationTests
   {
       [Theory]
       [InlineData("", false)] // Empty path should fail
       [InlineData("nonexistent.bin", false)] // Non-existent file should fail
       [InlineData("valid-payload.bin", true)] // Valid file should pass
       public async Task MemoryDumpCommand_ValidationScenarios(string payloadPath, bool shouldSucceed)
       {
           // Test validation scenarios
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Integration tests cover happy path scenarios
- [ ] Error scenarios are thoroughly tested
- [ ] Tests use realistic test data and mocks
- [ ] Tests run reliably in CI/CD pipeline

### 2.5.2 Update Application Integration
**Estimated Time**: 2 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Update Dependency Injection Configuration**
   ```csharp
   // In App.axaml.cs or Program.cs
   services.AddCommandHandlers();
   services.AddCommandValidation();
   services.AddPowerController();
   ```

2. **Update ViewModels to Use Commands**
   ```csharp
   public class MainWindowViewModel
   {
       private readonly ICommandHandler<MemoryDumpCommand, MemoryDumpResult> _memoryDumpHandler;
       
       public async Task ExecuteMemoryDumpAsync()
       {
           var command = new MemoryDumpCommand
           {
               Address = SelectedAddress,
               Length = DumpLength,
               PayloadPath = PayloadPath,
               OutputPath = OutputPath
           };
           
           var result = await _memoryDumpHandler.HandleAsync(command);
           // Handle result
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Application startup configures all command services
- [ ] ViewModels integrate with command handlers
- [ ] UI properly displays command results and errors
- [ ] Resource-based error messages are displayed

## Quality Gates

### Code Review Checklist
- [ ] No circular dependencies between projects
- [ ] Command pattern follows CQRS principles
- [ ] Validation is comprehensive and user-friendly
- [ ] Error handling uses resource-based messages
- [ ] All public APIs have XML documentation
- [ ] Unit tests achieve 90%+ coverage
- [ ] Integration tests cover critical scenarios

### Performance Criteria
- [ ] Command execution performance matches previous implementation
- [ ] Memory usage is stable during command execution
- [ ] UI remains responsive during long-running commands
- [ ] Validation overhead is minimal

### Architecture Compliance
- [ ] Single Responsibility Principle followed
- [ ] Open/Closed Principle enables extensibility
- [ ] Dependency Inversion eliminates circular dependencies
- [ ] Interface Segregation keeps contracts focused

## Risk Mitigation

### High-Risk Items
1. **Command Handler Complexity**
   - **Risk**: Complex command logic becomes hard to maintain
   - **Mitigation**: Keep handlers focused, use composition for complex scenarios
   - **Rollback**: Simplify command structure if needed

2. **Validation Performance**
   - **Risk**: Extensive validation slows down command execution
   - **Mitigation**: Profile validation pipeline, optimize critical paths
   - **Rollback**: Reduce validation scope if performance issues arise

### Monitoring
- [ ] Command execution times tracked
- [ ] Validation failure rates monitored
- [ ] Memory usage during command execution measured
- [ ] Error rates and types logged for analysis

## Success Criteria
- [ ] All command functionality restored without circular dependencies
- [ ] Command validation provides clear, actionable error messages
- [ ] Power controller abstraction enables testing and flexibility
- [ ] Integration tests verify end-to-end functionality
- [ ] Performance matches or exceeds previous implementation
- [ ] Code review approval obtained

---

**Phase Owner**: Senior Developer  
**Review Date**: End of implementation week  
**Next Phase**: Phase 3 - Advanced Features and Optimization