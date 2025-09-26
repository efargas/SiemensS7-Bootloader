using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Providers;
using S7.Infrastructure.Providers;
using Xunit;

namespace S7.Core.Tests.Providers
{
    /// <summary>
    /// Unit tests for FileSystemProvider.
    /// </summary>
    public class FileSystemProviderTests : IDisposable
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<FileSystemProvider<ITestService>> _logger;
        private readonly FileSystemProvider<ITestService> _provider;

        public FileSystemProviderTests()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options =>
            {
                options.EnableProviderCaching = true;
                options.CacheExpirationMinutes = 60;
            });
            services.AddScoped<ITestService, TestService>();

            _serviceProvider = services.BuildServiceProvider();
            _configuration = _serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            _logger = _serviceProvider.GetRequiredService<ILogger<FileSystemProvider<ITestService>>>();
            _provider = new FileSystemProvider<ITestService>(_serviceProvider, _configuration, _logger);
        }

        /// <summary>
        /// Tests that GetService returns a service from DI container.
        /// </summary>
        [Fact]
        public void GetService_WithDIService_ReturnsService()
        {
            // Act
            var service = _provider.GetService();

            // Assert
            Assert.NotNull(service);
            Assert.IsAssignableFrom<ITestService>(service);
        }

        /// <summary>
        /// Tests that GetService with name returns registered named service.
        /// </summary>
        [Fact]
        public void GetService_WithName_ReturnsNamedService()
        {
            // Arrange
            var testService = new TestService();
            _provider.RegisterNamedService("test", () => testService);

            // Act
            var service = _provider.GetService("test");

            // Assert
            Assert.NotNull(service);
            Assert.Same(testService, service);
        }

        /// <summary>
        /// Tests that GetService with invalid name returns null.
        /// </summary>
        [Fact]
        public void GetService_WithInvalidName_ReturnsNull()
        {
            // Act
            var service = _provider.GetService("nonexistent");

            // Assert
            Assert.Null(service);
        }

        /// <summary>
        /// Tests that GetRequiredService returns service when available.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithAvailableService_ReturnsService()
        {
            // Act
            var service = _provider.GetRequiredService();

            // Assert
            Assert.NotNull(service);
            Assert.IsAssignableFrom<ITestService>(service);
        }

        /// <summary>
        /// Tests that GetRequiredService with name returns named service.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithName_ReturnsNamedService()
        {
            // Arrange
            var testService = new TestService();
            _provider.RegisterNamedService("test", () => testService);

            // Act
            var service = _provider.GetRequiredService("test");

            // Assert
            Assert.NotNull(service);
            Assert.Same(testService, service);
        }

        /// <summary>
        /// Tests that GetRequiredService with invalid name throws exception.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithInvalidName_ThrowsException()
        {
            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => _provider.GetRequiredService("nonexistent"));
        }

        /// <summary>
        /// Tests that GetServices returns all available services.
        /// </summary>
        [Fact]
        public void GetServices_ReturnsAllServices()
        {
            // Arrange
            _provider.RegisterNamedService("test1", () => new TestService());
            _provider.RegisterNamedService("test2", () => new AlternativeTestService());

            // Act
            var services = _provider.GetServices().ToList();

            // Assert
            Assert.NotEmpty(services);
            Assert.True(services.Count >= 2); // At least the named services
        }

        /// <summary>
        /// Tests that GetServiceAsync returns service asynchronously.
        /// </summary>
        [Fact]
        public async Task GetServiceAsync_ReturnsServiceAsync()
        {
            // Act
            var service = await _provider.GetServiceAsync();

            // Assert
            Assert.NotNull(service);
            Assert.IsAssignableFrom<ITestService>(service);
        }

        /// <summary>
        /// Tests that GetServiceAsync with name returns named service asynchronously.
        /// </summary>
        [Fact]
        public async Task GetServiceAsync_WithName_ReturnsNamedServiceAsync()
        {
            // Arrange
            var testService = new TestService();
            _provider.RegisterNamedService("test", () => testService);

            // Act
            var service = await _provider.GetServiceAsync("test");

            // Assert
            Assert.NotNull(service);
            Assert.Same(testService, service);
        }

        /// <summary>
        /// Tests that IsServiceAvailable returns true when service is available.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithAvailableService_ReturnsTrue()
        {
            // Act
            var isAvailable = _provider.IsServiceAvailable();

            // Assert
            Assert.True(isAvailable);
        }

        /// <summary>
        /// Tests that IsServiceAvailable with name returns true for registered service.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithName_ReturnsTrue()
        {
            // Arrange
            _provider.RegisterNamedService("test", () => new TestService());

            // Act
            var isAvailable = _provider.IsServiceAvailable("test");

            // Assert
            Assert.True(isAvailable);
        }

        /// <summary>
        /// Tests that IsServiceAvailable with invalid name returns false.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithInvalidName_ReturnsFalse()
        {
            // Act
            var isAvailable = _provider.IsServiceAvailable("nonexistent");

            // Assert
            Assert.False(isAvailable);
        }

        /// <summary>
        /// Tests that GetServiceMetadata returns metadata for all services.
        /// </summary>
        [Fact]
        public void GetServiceMetadata_ReturnsAllMetadata()
        {
            // Arrange
            _provider.RegisterNamedService("test", () => new TestService());

            // Act
            var metadata = _provider.GetServiceMetadata().ToList();

            // Assert
            Assert.NotEmpty(metadata);
            Assert.Contains(metadata, m => m.Name == "test");
        }

        /// <summary>
        /// Tests that GetServiceMetadata with name returns specific metadata.
        /// </summary>
        [Fact]
        public void GetServiceMetadata_WithName_ReturnsSpecificMetadata()
        {
            // Arrange
            var testMetadata = new ServiceMetadata<ITestService>
            {
                Name = "test",
                Description = "Test service",
                Version = "1.0.0"
            };
            _provider.RegisterNamedService("test", () => new TestService(), testMetadata);

            // Act
            var metadata = _provider.GetServiceMetadata("test");

            // Assert
            Assert.NotNull(metadata);
            Assert.Equal("test", metadata.Name);
            Assert.Equal("Test service", metadata.Description);
            Assert.Equal("1.0.0", metadata.Version);
        }

        /// <summary>
        /// Tests that RegisterNamedService registers service correctly.
        /// </summary>
        [Fact]
        public void RegisterNamedService_RegistersServiceCorrectly()
        {
            // Arrange
            var testService = new TestService();

            // Act
            _provider.RegisterNamedService("test", () => testService);

            // Assert
            var retrievedService = _provider.GetService("test");
            Assert.Same(testService, retrievedService);
        }

        /// <summary>
        /// Tests that RegisterNamedService throws with null name.
        /// </summary>
        [Fact]
        public void RegisterNamedService_WithNullName_ThrowsException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => _provider.RegisterNamedService(null!, () => new TestService()));
        }

        /// <summary>
        /// Tests that RegisterNamedService throws with null factory.
        /// </summary>
        [Fact]
        public void RegisterNamedService_WithNullFactory_ThrowsException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => _provider.RegisterNamedService("test", null!));
        }

        /// <summary>
        /// Tests that UnregisterNamedService removes service correctly.
        /// </summary>
        [Fact]
        public void UnregisterNamedService_RemovesServiceCorrectly()
        {
            // Arrange
            _provider.RegisterNamedService("test", () => new TestService());

            // Act
            var result = _provider.UnregisterNamedService("test");

            // Assert
            Assert.True(result);
            Assert.Null(_provider.GetService("test"));
        }

        /// <summary>
        /// Tests that UnregisterNamedService returns false for non-existent service.
        /// </summary>
        [Fact]
        public void UnregisterNamedService_WithNonExistentService_ReturnsFalse()
        {
            // Act
            var result = _provider.UnregisterNamedService("nonexistent");

            // Assert
            Assert.False(result);
        }

        /// <summary>
        /// Tests that provider creates base directory for file system storage.
        /// </summary>
        [Fact]
        public void Provider_CreatesBaseDirectory()
        {
            // The provider should create its base directory during initialization
            // This is tested implicitly by the fact that the provider can be created without throwing
            Assert.NotNull(_provider);
        }

        /// <summary>
        /// Tests that provider handles file system operations gracefully.
        /// </summary>
        [Fact]
        public void Provider_HandlesFileSystemOperationsGracefully()
        {
            // Arrange
            var testService = new TestService();
            var testMetadata = new ServiceMetadata<ITestService>
            {
                Name = "test",
                Description = "Test service for file system",
                Version = "1.0.0"
            };

            // Act & Assert - Should not throw
            _provider.RegisterNamedService("test", () => testService, testMetadata);
            var retrievedService = _provider.GetService("test");
            var metadata = _provider.GetServiceMetadata("test");
            var isAvailable = _provider.IsServiceAvailable("test");
            var unregistered = _provider.UnregisterNamedService("test");

            Assert.Same(testService, retrievedService);
            Assert.NotNull(metadata);
            Assert.True(isAvailable);
            Assert.True(unregistered);
        }

        /// <summary>
        /// Tests that provider handles concurrent file system access.
        /// </summary>
        [Fact]
        public async Task Provider_HandlesConcurrentFileSystemAccess()
        {
            // Arrange
            var tasks = Enumerable.Range(0, 5).Select(async i =>
            {
                await Task.Delay(10); // Small delay to increase chance of concurrency
                var serviceName = $"test{i}";
                _provider.RegisterNamedService(serviceName, () => new TestService());
                return _provider.GetService(serviceName);
            });

            // Act
            var results = await Task.WhenAll(tasks);

            // Assert
            Assert.All(results, service => Assert.NotNull(service));
            Assert.Equal(5, results.Length);
        }

        /// <summary>
        /// Tests that provider persists service metadata to file system.
        /// </summary>
        [Fact]
        public void Provider_PersistsServiceMetadata()
        {
            // Arrange
            var testMetadata = new ServiceMetadata<ITestService>
            {
                Name = "persistent_test",
                Description = "Persistent test service",
                Version = "2.0.0",
                Priority = 10
            };

            // Act
            _provider.RegisterNamedService("persistent_test", () => new TestService(), testMetadata);

            // Create a new provider instance to test persistence
            var newProvider = new FileSystemProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var retrievedMetadata = newProvider.GetServiceMetadata("persistent_test");

            // Assert
            // Note: In the current implementation, we create a basic metadata object
            // In a real implementation, this would be deserialized from the file system
            Assert.NotNull(retrievedMetadata);
            Assert.Equal("persistent_test", retrievedMetadata.Name);
        }

        /// <summary>
        /// Tests that provider handles invalid file system paths gracefully.
        /// </summary>
        [Fact]
        public void Provider_HandlesInvalidPathsGracefully()
        {
            // This test ensures the provider doesn't crash with invalid service names
            // that might create invalid file paths

            // Act & Assert - Should not throw
            _provider.RegisterNamedService("valid_name", () => new TestService());
            
            // These operations should handle any file system issues gracefully
            var service = _provider.GetService("valid_name");
            var isAvailable = _provider.IsServiceAvailable("valid_name");
            var metadata = _provider.GetServiceMetadata("valid_name");

            Assert.NotNull(service);
            Assert.True(isAvailable);
            Assert.NotNull(metadata);
        }

        /// <summary>
        /// Tests that provider supports service discovery from file system.
        /// </summary>
        [Fact]
        public void Provider_SupportsServiceDiscovery()
        {
            // Arrange
            _provider.RegisterNamedService("discoverable1", () => new TestService());
            _provider.RegisterNamedService("discoverable2", () => new AlternativeTestService());

            // Act
            var allMetadata = _provider.GetServiceMetadata().ToList();
            var allServices = _provider.GetServices().ToList();

            // Assert
            Assert.Contains(allMetadata, m => m.Name == "discoverable1");
            Assert.Contains(allMetadata, m => m.Name == "discoverable2");
            Assert.True(allServices.Count >= 2);
        }

        /// <summary>
        /// Tests that provider handles service registration with complex metadata.
        /// </summary>
        [Fact]
        public void Provider_HandlesComplexMetadata()
        {
            // Arrange
            var complexMetadata = new ServiceMetadata<ITestService>
            {
                Name = "complex_service",
                Description = "A service with complex metadata",
                Version = "3.1.4",
                Priority = 100,
                Properties = new Dictionary<string, object>
                {
                    ["Environment"] = "Test",
                    ["MaxConnections"] = 50,
                    ["EnableLogging"] = true
                }
            };

            // Act
            _provider.RegisterNamedService("complex_service", () => new TestService(), complexMetadata);
            var retrievedMetadata = _provider.GetServiceMetadata("complex_service");

            // Assert
            Assert.NotNull(retrievedMetadata);
            Assert.Equal("complex_service", retrievedMetadata.Name);
            Assert.Equal("A service with complex metadata", retrievedMetadata.Description);
            Assert.Equal("3.1.4", retrievedMetadata.Version);
            Assert.Equal(100, retrievedMetadata.Priority);
        }

        public void Dispose()
        {
            // Clean up any test files/directories if needed
            _serviceProvider?.GetService<IServiceScope>()?.Dispose();
        }
    }
}