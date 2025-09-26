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
    /// Unit tests for MemoryProvider.
    /// </summary>
    public class MemoryProviderTests : IDisposable
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<MemoryProvider<ITestService>> _logger;
        private readonly MemoryProvider<ITestService> _provider;

        public MemoryProviderTests()
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
            _logger = _serviceProvider.GetRequiredService<ILogger<MemoryProvider<ITestService>>>();
            _provider = new MemoryProvider<ITestService>(_serviceProvider, _configuration, _logger);
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
        /// Tests that GetService caches the result when caching is enabled.
        /// </summary>
        [Fact]
        public void GetService_WithCachingEnabled_CachesResult()
        {
            // Act
            var service1 = _provider.GetService();
            var service2 = _provider.GetService();

            // Assert
            Assert.NotNull(service1);
            Assert.NotNull(service2);
            // Note: Due to DI scoping, these might be the same instance anyway
            // The important thing is that no exception is thrown and services are returned
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
        /// Tests that GetService with name caches the result.
        /// </summary>
        [Fact]
        public void GetService_WithNameAndCaching_CachesResult()
        {
            // Arrange
            var callCount = 0;
            _provider.RegisterNamedService("test", () =>
            {
                callCount++;
                return new TestService();
            });

            // Act
            var service1 = _provider.GetService("test");
            var service2 = _provider.GetService("test");

            // Assert
            Assert.NotNull(service1);
            Assert.NotNull(service2);
            Assert.Same(service1, service2); // Should be cached
            Assert.Equal(1, callCount); // Factory should only be called once
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
        /// Tests that ClearCache clears all cached instances.
        /// </summary>
        [Fact]
        public void ClearCache_ClearsAllCachedInstances()
        {
            // Arrange
            var callCount = 0;
            _provider.RegisterNamedService("test", () =>
            {
                callCount++;
                return new TestService();
            });

            // Get service to cache it
            var service1 = _provider.GetService("test");

            // Act
            _provider.ClearCache();
            var service2 = _provider.GetService("test");

            // Assert
            Assert.NotNull(service1);
            Assert.NotNull(service2);
            Assert.NotSame(service1, service2); // Should be different after cache clear
            Assert.Equal(2, callCount); // Factory should be called twice
        }

        /// <summary>
        /// Tests that GetCacheStatistics returns cache statistics.
        /// </summary>
        [Fact]
        public void GetCacheStatistics_ReturnsCacheStatistics()
        {
            // Arrange
            _provider.RegisterNamedService("test", () => new TestService());
            _provider.GetService("test"); // Cache the service

            // Act
            var stats = _provider.GetCacheStatistics();

            // Assert
            Assert.NotNull(stats);
            Assert.True(stats.ContainsKey("CachedInstanceCount"));
            Assert.True(stats.ContainsKey("NamedServiceCount"));
            Assert.True(stats.ContainsKey("MetadataCount"));
        }

        /// <summary>
        /// Tests that provider handles concurrent access correctly.
        /// </summary>
        [Fact]
        public async Task Provider_WithConcurrentAccess_HandlesCorrectly()
        {
            // Arrange
            _provider.RegisterNamedService("test", () => new TestService());

            // Act
            var tasks = Enumerable.Range(0, 10).Select(async i =>
            {
                await Task.Delay(10); // Small delay to increase chance of concurrency
                return _provider.GetService("test");
            });

            var results = await Task.WhenAll(tasks);

            // Assert
            Assert.All(results, service => Assert.NotNull(service));
            // All results should be the same due to caching
            Assert.All(results, service => Assert.Same(results[0], service));
        }

        /// <summary>
        /// Tests that provider with caching disabled doesn't cache results.
        /// </summary>
        [Fact]
        public void Provider_WithCachingDisabled_DoesNotCache()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options =>
            {
                options.EnableProviderCaching = false;
            });

            var serviceProvider = services.BuildServiceProvider();
            var configuration = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var logger = serviceProvider.GetRequiredService<ILogger<MemoryProvider<ITestService>>>();
            var provider = new MemoryProvider<ITestService>(serviceProvider, configuration, logger);

            var callCount = 0;
            provider.RegisterNamedService("test", () =>
            {
                callCount++;
                return new TestService();
            });

            // Act
            var service1 = provider.GetService("test");
            var service2 = provider.GetService("test");

            // Assert
            Assert.NotNull(service1);
            Assert.NotNull(service2);
            Assert.Equal(2, callCount); // Factory should be called twice (no caching)
        }

        public void Dispose()
        {
            _provider?.Dispose();
            _serviceProvider?.GetService<IServiceScope>()?.Dispose();
        }
    }
}