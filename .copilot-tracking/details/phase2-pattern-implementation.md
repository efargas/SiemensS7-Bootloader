# Phase 2: Pattern Implementation - Detailed Implementation Plan

## Overview
Phase 2 focuses on implementing missing design patterns to create a robust, maintainable architecture. This phase builds upon the foundation established in Phase 1.

**Duration**: 2 weeks  
**Priority**: HIGH  
**Dependencies**: Phase 1 completion

## Task 2.1: Repository Pattern Implementation

### 2.1.1 Design Repository Interfaces
**Estimated Time**: 4 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create Base Repository Interface**
   ```csharp
   public interface IRepository<TEntity, TKey> where TEntity : class
   {
       Task<TEntity?> GetByIdAsync(TKey id, CancellationToken cancellationToken = default);
       Task<IEnumerable<TEntity>> GetAllAsync(CancellationToken cancellationToken = default);
       Task<TEntity> AddAsync(TEntity entity, CancellationToken cancellationToken = default);
       Task<TEntity> UpdateAsync(TEntity entity, CancellationToken cancellationToken = default);
       Task DeleteAsync(TKey id, CancellationToken cancellationToken = default);
       Task<bool> ExistsAsync(TKey id, CancellationToken cancellationToken = default);
   }
   ```

2. **Create Configuration Repository Interface**
   ```csharp
   public interface IConfigurationRepository
   {
       Task<ApplicationConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default);
       Task SaveConfigurationAsync(ApplicationConfiguration configuration, CancellationToken cancellationToken = default);
       Task<T> GetSettingAsync<T>(string key, T defaultValue = default, CancellationToken cancellationToken = default);
       Task SetSettingAsync<T>(string key, T value, CancellationToken cancellationToken = default);
       Task<bool> SettingExistsAsync(string key, CancellationToken cancellationToken = default);
   }
   ```

3. **Create Profile Repository Interface**
   ```csharp
   public interface IProfileRepository
   {
       Task<IEnumerable<ConnectionProfile>> GetAllProfilesAsync(CancellationToken cancellationToken = default);
       Task<ConnectionProfile?> GetProfileByNameAsync(string name, CancellationToken cancellationToken = default);
       Task<ConnectionProfile> SaveProfileAsync(ConnectionProfile profile, CancellationToken cancellationToken = default);
       Task DeleteProfileAsync(string name, CancellationToken cancellationToken = default);
       Task<ConnectionProfile?> GetDefaultProfileAsync(CancellationToken cancellationToken = default);
       Task SetDefaultProfileAsync(string name, CancellationToken cancellationToken = default);
   }
   ```

4. **Create Dump Repository Interface**
   ```csharp
   public interface IDumpRepository
   {
       Task<IEnumerable<DumpMetadata>> GetDumpMetadataAsync(CancellationToken cancellationToken = default);
       Task<DumpMetadata?> GetDumpMetadataByIdAsync(Guid id, CancellationToken cancellationToken = default);
       Task<DumpMetadata> SaveDumpMetadataAsync(DumpMetadata metadata, CancellationToken cancellationToken = default);
       Task<byte[]> GetDumpDataAsync(Guid id, CancellationToken cancellationToken = default);
       Task SaveDumpDataAsync(Guid id, byte[] data, CancellationToken cancellationToken = default);
       Task DeleteDumpAsync(Guid id, CancellationToken cancellationToken = default);
   }
   ```

#### Acceptance Criteria:
- [ ] All repository interfaces follow consistent patterns
- [ ] Async methods with cancellation token support
- [ ] Proper generic constraints where applicable
- [ ] XML documentation for all public members

### 2.1.2 Implement File-Based Repositories
**Estimated Time**: 8 hours  
**Assignee**: Mid-level Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create Base File Repository**
   ```csharp
   public abstract class FileRepositoryBase<TEntity, TKey> : IRepository<TEntity, TKey>
       where TEntity : class, IIdentifiable<TKey>
   {
       protected readonly string _dataDirectory;
       protected readonly ILogger _logger;
       protected readonly JsonSerializerOptions _jsonOptions;
       
       protected FileRepositoryBase(string dataDirectory, ILogger logger)
       {
           _dataDirectory = dataDirectory ?? throw new ArgumentNullException(nameof(dataDirectory));
           _logger = logger ?? throw new ArgumentNullException(nameof(logger));
           _jsonOptions = new JsonSerializerOptions
           {
               PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
               WriteIndented = true
           };
           
           Directory.CreateDirectory(_dataDirectory);
       }
       
       protected abstract string GetFileName(TKey id);
       protected abstract TKey GetEntityId(TEntity entity);
   }
   ```

2. **Implement Configuration Repository**
   ```csharp
   public class FileConfigurationRepository : IConfigurationRepository
   {
       private readonly string _configFilePath;
       private readonly ILogger<FileConfigurationRepository> _logger;
       private readonly SemaphoreSlim _fileLock;
       
       public FileConfigurationRepository(string configDirectory, ILogger<FileConfigurationRepository> logger)
       {
           _configFilePath = Path.Combine(configDirectory, "application.json");
           _logger = logger;
           _fileLock = new SemaphoreSlim(1, 1);
           
           Directory.CreateDirectory(configDirectory);
       }
       
       public async Task<ApplicationConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default)
       {
           await _fileLock.WaitAsync(cancellationToken);
           try
           {
               if (!File.Exists(_configFilePath))
               {
                   var defaultConfig = ApplicationConfiguration.CreateDefault();
                   await SaveConfigurationAsync(defaultConfig, cancellationToken);
                   return defaultConfig;
               }
               
               var json = await File.ReadAllTextAsync(_configFilePath, cancellationToken);
               return JsonSerializer.Deserialize<ApplicationConfiguration>(json) ?? ApplicationConfiguration.CreateDefault();
           }
           finally
           {
               _fileLock.Release();
           }
       }
   }
   ```

3. **Implement Profile Repository**
   ```csharp
   public class FileProfileRepository : FileRepositoryBase<ConnectionProfile, string>, IProfileRepository
   {
       private const string DefaultProfileFileName = "_default.json";
       
       public FileProfileRepository(string profilesDirectory, ILogger<FileProfileRepository> logger)
           : base(profilesDirectory, logger)
       {
       }
       
       protected override string GetFileName(string name) => $"{name}.json";
       protected override string GetEntityId(ConnectionProfile entity) => entity.Name;
       
       public async Task<ConnectionProfile?> GetDefaultProfileAsync(CancellationToken cancellationToken = default)
       {
           var defaultFile = Path.Combine(_dataDirectory, DefaultProfileFileName);
           if (!File.Exists(defaultFile))
               return null;
               
           var json = await File.ReadAllTextAsync(defaultFile, cancellationToken);
           var defaultInfo = JsonSerializer.Deserialize<DefaultProfileInfo>(json);
           
           return defaultInfo?.ProfileName != null 
               ? await GetProfileByNameAsync(defaultInfo.ProfileName, cancellationToken)
               : null;
       }
   }
   ```

#### Acceptance Criteria:
- [ ] All repositories implement their interfaces correctly
- [ ] File operations are thread-safe
- [ ] Proper error handling and logging
- [ ] Configuration validation on load/save
- [ ] Unit tests for all repository operations

### 2.1.3 Implement Unit of Work Pattern
**Estimated Time**: 4 hours  
**Assignee**: Senior Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **Create Unit of Work Interface**
   ```csharp
   public interface IUnitOfWork : IDisposable
   {
       IConfigurationRepository Configurations { get; }
       IProfileRepository Profiles { get; }
       IDumpRepository Dumps { get; }
       
       Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
       Task BeginTransactionAsync(CancellationToken cancellationToken = default);
       Task CommitTransactionAsync(CancellationToken cancellationToken = default);
       Task RollbackTransactionAsync(CancellationToken cancellationToken = default);
   }
   ```

2. **Implement File-Based Unit of Work**
   ```csharp
   public class FileUnitOfWork : IUnitOfWork
   {
       private readonly ILogger<FileUnitOfWork> _logger;
       private readonly List<Func<CancellationToken, Task>> _pendingOperations;
       private bool _disposed;
       
       public IConfigurationRepository Configurations { get; }
       public IProfileRepository Profiles { get; }
       public IDumpRepository Dumps { get; }
       
       public FileUnitOfWork(
           IConfigurationRepository configurationRepository,
           IProfileRepository profileRepository,
           IDumpRepository dumpRepository,
           ILogger<FileUnitOfWork> logger)
       {
           Configurations = configurationRepository;
           Profiles = profileRepository;
           Dumps = dumpRepository;
           _logger = logger;
           _pendingOperations = new List<Func<CancellationToken, Task>>();
       }
       
       public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
       {
           var operationCount = _pendingOperations.Count;
           
           foreach (var operation in _pendingOperations)
           {
               await operation(cancellationToken);
           }
           
           _pendingOperations.Clear();
           return operationCount;
       }
   }
   ```

## Task 2.2: Factory Pattern Enhancement

### 2.2.1 Implement PlcClient Factory
**Estimated Time**: 4 hours  
**Assignee**: Senior Developer  
**Priority**: HIGH

#### Implementation Steps:
1. **Create PlcClient Factory Interface**
   ```csharp
   public interface IPlcClientFactory
   {
       Task<PlcClient> CreateAsync(CommunicationChannelConfig config, CancellationToken cancellationToken = default);
       Task<PlcClient> CreateAsync(ConnectionProfile profile, CancellationToken cancellationToken = default);
       PlcClient Create(ICommunicationChannel channel, Action<string> logger);
   }
   ```

2. **Implement PlcClient Factory**
   ```csharp
   public class PlcClientFactory : IPlcClientFactory
   {
       private readonly ICommunicationChannelProvider _channelProvider;
       private readonly ILogger<PlcClientFactory> _logger;
       private readonly IServiceProvider _serviceProvider;
       
       public PlcClientFactory(
           ICommunicationChannelProvider channelProvider,
           ILogger<PlcClientFactory> logger,
           IServiceProvider serviceProvider)
       {
           _channelProvider = channelProvider;
           _logger = logger;
           _serviceProvider = serviceProvider;
       }
       
       public async Task<PlcClient> CreateAsync(CommunicationChannelConfig config, CancellationToken cancellationToken = default)
       {
           var channel = _channelProvider.CreateChannel(config);
           await channel.ConnectAsync(cancellationToken);
           
           var clientLogger = CreateClientLogger();
           var client = new PlcClient(channel, clientLogger);
           
           return client;
       }
       
       private Action<string> CreateClientLogger()
       {
           return message => _logger.LogInformation("PlcClient: {Message}", message);
       }
   }
   ```

3. **Create Communication Channel Factory**
   ```csharp
   public interface ICommunicationChannelFactory
   {
       ICommunicationChannel CreateTcpChannel(string host, int port);
       ICommunicationChannel CreateSerialChannel(string portName, int baudRate, Parity parity, StopBits stopBits, Handshake flowControl);
       ICommunicationChannel CreateChannel(CommunicationChannelConfig config);
   }
   
   public class CommunicationChannelFactory : ICommunicationChannelFactory
   {
       public ICommunicationChannel CreateTcpChannel(string host, int port)
       {
           return new TcpChannel(host, port);
       }
       
       public ICommunicationChannel CreateSerialChannel(string portName, int baudRate, Parity parity, StopBits stopBits, Handshake flowControl)
       {
           return new SerialChannel(portName, baudRate, parity, stopBits, flowControl);
       }
       
       public ICommunicationChannel CreateChannel(CommunicationChannelConfig config)
       {
           return config.Mode.ToUpperInvariant() switch
           {
               "TCP" => CreateTcpChannel(config.Host ?? "localhost", config.Port),
               "SERIAL" => CreateSerialChannel(config.SerialPort ?? throw new ArgumentException("Serial port required"), 
                                             config.BaudRate, config.Parity, config.StopBits, config.FlowControl),
               _ => throw new ArgumentException($"Unsupported communication mode: {config.Mode}")
           };
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Factory creates properly configured PlcClient instances
- [ ] Proper dependency injection integration
- [ ] Error handling for invalid configurations
- [ ] Unit tests for all factory methods

### 2.2.2 Implement Service Factory Pattern
**Estimated Time**: 3 hours  
**Assignee**: Mid-level Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **Create Service Factory Interface**
   ```csharp
   public interface IServiceFactory<T>
   {
       T Create();
       T Create(string name);
       T Create(IServiceProvider serviceProvider);
   }
   ```

2. **Implement Logging Service Factory**
   ```csharp
   public class LoggingServiceFactory : IServiceFactory<ILoggingService>
   {
       private readonly IServiceProvider _serviceProvider;
       
       public LoggingServiceFactory(IServiceProvider serviceProvider)
       {
           _serviceProvider = serviceProvider;
       }
       
       public ILoggingService Create()
       {
           return Create("default");
       }
       
       public ILoggingService Create(string name)
       {
           var dispatcher = _serviceProvider.GetRequiredService<Dispatcher>();
           var configuration = _serviceProvider.GetRequiredService<ApplicationConfiguration>();
           
           return new LoggingService(dispatcher, configuration.LogsPath);
       }
       
       public ILoggingService Create(IServiceProvider serviceProvider)
       {
           return serviceProvider.GetRequiredService<ILoggingService>();
       }
   }
   ```

## Task 2.3: Provider Pattern Completion

### 2.3.1 Implement Configuration-Driven Providers
**Estimated Time**: 4 hours  
**Assignee**: Senior Developer  
**Priority**: MEDIUM

#### Implementation Steps:
1. **Create Provider Registry**
   ```csharp
   public interface IProviderRegistry<T>
   {
       void RegisterProvider(string name, Func<IServiceProvider, T> factory);
       T GetProvider(string name);
       IEnumerable<string> GetProviderNames();
       bool IsProviderRegistered(string name);
   }
   
   public class ProviderRegistry<T> : IProviderRegistry<T>
   {
       private readonly Dictionary<string, Func<IServiceProvider, T>> _providers;
       private readonly IServiceProvider _serviceProvider;
       
       public ProviderRegistry(IServiceProvider serviceProvider)
       {
           _providers = new Dictionary<string, Func<IServiceProvider, T>>(StringComparer.OrdinalIgnoreCase);
           _serviceProvider = serviceProvider;
       }
       
       public void RegisterProvider(string name, Func<IServiceProvider, T> factory)
       {
           _providers[name] = factory;
       }
       
       public T GetProvider(string name)
       {
           if (!_providers.TryGetValue(name, out var factory))
           {
               throw new ArgumentException($"Provider '{name}' is not registered");
           }
           
           return factory(_serviceProvider);
       }
   }
   ```

2. **Enhance Communication Channel Provider**
   ```csharp
   public class CommunicationChannelProvider : ICommunicationChannelProvider
   {
       private readonly IProviderRegistry<ICommunicationChannel> _registry;
       private readonly ILogger<CommunicationChannelProvider> _logger;
       
       public CommunicationChannelProvider(
           IProviderRegistry<ICommunicationChannel> registry,
           ILogger<CommunicationChannelProvider> logger)
       {
           _registry = registry;
           _logger = logger;
           
           RegisterDefaultProviders();
       }
       
       private void RegisterDefaultProviders()
       {
           _registry.RegisterProvider("TCP", sp => 
           {
               var config = sp.GetRequiredService<CommunicationChannelConfig>();
               return new TcpChannel(config.Host ?? "localhost", config.Port);
           });
           
           _registry.RegisterProvider("SERIAL", sp =>
           {
               var config = sp.GetRequiredService<CommunicationChannelConfig>();
               return new SerialChannel(config.SerialPort!, config.BaudRate, config.Parity, config.StopBits, config.FlowControl);
           });
       }
       
       public ICommunicationChannel CreateChannel(CommunicationChannelConfig config)
       {
           return _registry.GetProvider(config.Mode);
       }
       
       public IEnumerable<string> GetSupportedModes()
       {
           return _registry.GetProviderNames();
       }
   }
   ```

#### Acceptance Criteria:
- [ ] Provider registry supports dynamic registration
- [ ] Configuration-driven provider selection
- [ ] Proper error handling for unknown providers
- [ ] Unit tests for provider registration and selection

## Testing Strategy

### Unit Tests
**Estimated Time**: 8 hours  
**Assignee**: Mid-level Developer

#### Test Coverage Requirements:
- [ ] Repository implementations: 90% coverage
- [ ] Factory implementations: 85% coverage
- [ ] Provider implementations: 85% coverage
- [ ] Unit of Work pattern: 90% coverage

#### Test Categories:
1. **Repository Tests**
   - CRUD operations
   - Concurrency handling
   - Error scenarios
   - File system interactions

2. **Factory Tests**
   - Object creation with various configurations
   - Dependency injection integration
   - Error handling for invalid inputs

3. **Provider Tests**
   - Provider registration and retrieval
   - Configuration-driven selection
   - Error handling for missing providers

### Integration Tests
**Estimated Time**: 6 hours  
**Assignee**: Senior Developer

#### Test Scenarios:
1. **End-to-End Repository Operations**
   - Configuration save/load with validation
   - Profile management workflows
   - Dump metadata and data operations

2. **Factory Integration**
   - PlcClient creation with real channels
   - Service factory with DI container
   - Error propagation and handling

3. **Provider Integration**
   - Channel provider with different configurations
   - Dynamic provider registration
   - Configuration changes affecting provider selection

## Quality Gates

### Code Review Checklist
- [ ] Repository pattern correctly implemented
- [ ] Factory pattern follows DI best practices
- [ ] Provider pattern supports extensibility
- [ ] All interfaces properly documented
- [ ] Error handling is consistent
- [ ] Async patterns used correctly

### Performance Criteria
- [ ] Repository operations complete within acceptable time
- [ ] Factory creation doesn't introduce memory leaks
- [ ] Provider selection is efficient
- [ ] No performance regression in existing functionality

### Architecture Compliance
- [ ] SOLID principles followed
- [ ] Dependency injection used throughout
- [ ] Interfaces properly abstracted
- [ ] Separation of concerns maintained

## Risk Mitigation

### High-Risk Items
1. **Repository File Operations**
   - **Risk**: File corruption or concurrent access issues
   - **Mitigation**: File locking and atomic operations
   - **Rollback**: In-memory fallback implementation

2. **Factory Dependency Changes**
   - **Risk**: Breaking existing object creation
   - **Mitigation**: Backward compatibility wrappers
   - **Rollback**: Direct instantiation fallback

### Monitoring
- [ ] File system operation monitoring
- [ ] Memory usage tracking for factories
- [ ] Provider selection performance metrics
- [ ] Error rate monitoring for new patterns

## Deliverables

### Week 3 Deliverables
- [ ] Repository interfaces and implementations
- [ ] Unit of Work pattern implementation
- [ ] Factory pattern enhancements
- [ ] Initial provider pattern improvements

### Week 4 Deliverables
- [ ] Provider pattern completion
- [ ] All unit tests implemented and passing
- [ ] Integration tests implemented
- [ ] Performance testing completed
- [ ] Documentation updated

## Success Criteria
- [ ] Repository pattern fully functional
- [ ] Factory pattern integrated with DI
- [ ] Provider pattern supports configuration
- [ ] All tests passing with required coverage
- [ ] No breaking changes to existing APIs
- [ ] Performance requirements met
- [ ] Code review approval obtained

---

**Phase Owner**: Senior Developer  
**Review Date**: End of Week 3 and Week 4  
**Next Phase**: Phase 3 - Quality & Testing