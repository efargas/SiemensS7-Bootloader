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
    /// Unit tests for DefaultServiceProvider.
    /// </summary>
    public class DefaultServiceProviderTests
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<DefaultServiceProvider<ITestService>> _logger;

        public DefaultServiceProviderTests()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options => { });
            services.AddScoped<ITestService, TestService>();
            services.AddScoped<ITestService, AlternativeTestService>();

            _serviceProvider = services.BuildServiceProvider();
            _configuration = _serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            _logger = _serviceProvider.GetRequiredService<ILogger<DefaultServiceProvider<ITestService>>>();
        }

        /// <summary>
        /// Tests that GetService returns a service from DI container.
        /// </summary>
        [Fact]
        public void GetService_WithDIService_ReturnsService()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var service = provider.GetService();

            // Assert
            Assert.NotNull(service);
            Assert.IsAssignableFrom<ITestService>(service);
        }

        /// <summary>
        /// Tests that GetService returns null when no service is available.
        /// </summary>
        [Fact]
        public void GetService_WithNoService_ReturnsNull()
        {
            // Arrange
            var emptyServices = new ServiceCollection();
            emptyServices.AddLogging();
            emptyServices.Configure<ProviderConfiguration>(options => { });
            var emptyServiceProvider = emptyServices.BuildServiceProvider();
            var emptyConfiguration = emptyServiceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var emptyLogger = emptyServiceProvider.GetRequiredService<ILogger<DefaultServiceProvider<INonExistentService>>>();

            var provider = new DefaultServiceProvider<INonExistentService>(emptyServiceProvider, emptyConfiguration, emptyLogger);

            // Act
            var service = provider.GetService();

            // Assert
            Assert.Null(service);
        }

        /// <summary>
        /// Tests that GetService with name returns registered named service.
        /// </summary>
        [Fact]
        public void GetService_WithName_ReturnsNamedService()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var testService = new TestService();
            provider.RegisterNamedService("test", () => testService);

            // Act
            var service = provider.GetService("test");

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
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var service = provider.GetService("nonexistent");

            // Assert
            Assert.Null(service);
        }

        /// <summary>
        /// Tests that GetRequiredService returns service when available.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithAvailableService_ReturnsService()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var service = provider.GetRequiredService();

            // Assert
            Assert.NotNull(service);
            Assert.IsAssignableFrom<ITestService>(service);
        }

        /// <summary>
        /// Tests that GetRequiredService throws when service is not available.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithNoService_ThrowsException()
        {
            // Arrange
            var emptyServices = new ServiceCollection();
            emptyServices.AddLogging();
            emptyServices.Configure<ProviderConfiguration>(options => { });
            var emptyServiceProvider = emptyServices.BuildServiceProvider();
            var emptyConfiguration = emptyServiceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var emptyLogger = emptyServiceProvider.GetRequiredService<ILogger<DefaultServiceProvider<INonExistentService>>>();

            var provider = new DefaultServiceProvider<INonExistentService>(emptyServiceProvider, emptyConfiguration, emptyLogger);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService());
        }

        /// <summary>
        /// Tests that GetRequiredService with name returns named service.
        /// </summary>
        [Fact]
        public void GetRequiredService_WithName_ReturnsNamedService()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var testService = new TestService();
            provider.RegisterNamedService("test", () => testService);

            // Act
            var service = provider.GetRequiredService("test");

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
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService("nonexistent"));
        }

        /// <summary>
        /// Tests that GetServices returns all available services.
        /// </summary>
        [Fact]
        public void GetServices_ReturnsAllServices()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            provider.RegisterNamedService("test1", () => new TestService());
            provider.RegisterNamedService("test2", () => new AlternativeTestService());

            // Act
            var services = provider.GetServices().ToList();

            // Assert
            Assert.NotEmpty(services);
            Assert.True(services.Count >= 2); // At least the DI services plus named services
        }

        /// <summary>
        /// Tests that GetServiceAsync returns service asynchronously.
        /// </summary>
        [Fact]
        public async Task GetServiceAsync_ReturnsServiceAsync()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var service = await provider.GetServiceAsync();

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
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var testService = new TestService();
            provider.RegisterNamedService("test", () => testService);

            // Act
            var service = await provider.GetServiceAsync("test");

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
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var isAvailable = provider.IsServiceAvailable();

            // Assert
            Assert.True(isAvailable);
        }

        /// <summary>
        /// Tests that IsServiceAvailable returns false when no service is available.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithNoService_ReturnsFalse()
        {
            // Arrange
            var emptyServices = new ServiceCollection();
            emptyServices.AddLogging();
            emptyServices.Configure<ProviderConfiguration>(options => { });
            var emptyServiceProvider = emptyServices.BuildServiceProvider();
            var emptyConfiguration = emptyServiceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var emptyLogger = emptyServiceProvider.GetRequiredService<ILogger<DefaultServiceProvider<INonExistentService>>>();

            var provider = new DefaultServiceProvider<INonExistentService>(emptyServiceProvider, emptyConfiguration, emptyLogger);

            // Act
            var isAvailable = provider.IsServiceAvailable();

            // Assert
            Assert.False(isAvailable);
        }

        /// <summary>
        /// Tests that IsServiceAvailable with name returns true for registered service.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithName_ReturnsTrue()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            provider.RegisterNamedService("test", () => new TestService());

            // Act
            var isAvailable = provider.IsServiceAvailable("test");

            // Assert
            Assert.True(isAvailable);
        }

        /// <summary>
        /// Tests that IsServiceAvailable with invalid name returns false.
        /// </summary>
        [Fact]
        public void IsServiceAvailable_WithInvalidName_ReturnsFalse()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var isAvailable = provider.IsServiceAvailable("nonexistent");

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
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            provider.RegisterNamedService("test", () => new TestService());

            // Act
            var metadata = provider.GetServiceMetadata().ToList();

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
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var testMetadata = new ServiceMetadata<ITestService>
            {
                Name = "test",
                Description = "Test service",
                Version = "1.0.0"
            };
            provider.RegisterNamedService("test", () => new TestService(), testMetadata);

            // Act
            var metadata = provider.GetServiceMetadata("test");

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
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            var testService = new TestService();

            // Act
            provider.RegisterNamedService("test", () => testService);

            // Assert
            var retrievedService = provider.GetService("test");
            Assert.Same(testService, retrievedService);
        }

        /// <summary>
        /// Tests that RegisterNamedService throws with null name.
        /// </summary>
        [Fact]
        public void RegisterNamedService_WithNullName_ThrowsException()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => provider.RegisterNamedService(null!, () => new TestService()));
        }

        /// <summary>
        /// Tests that RegisterNamedService throws with null factory.
        /// </summary>
        [Fact]
        public void RegisterNamedService_WithNullFactory_ThrowsException()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => provider.RegisterNamedService("test", null!));
        }

        /// <summary>
        /// Tests that UnregisterNamedService removes service correctly.
        /// </summary>
        [Fact]
        public void UnregisterNamedService_RemovesServiceCorrectly()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);
            provider.RegisterNamedService("test", () => new TestService());

            // Act
            var result = provider.UnregisterNamedService("test");

            // Assert
            Assert.True(result);
            Assert.Null(provider.GetService("test"));
        }

        /// <summary>
        /// Tests that UnregisterNamedService returns false for non-existent service.
        /// </summary>
        [Fact]
        public void UnregisterNamedService_WithNonExistentService_ReturnsFalse()
        {
            // Arrange
            var provider = new DefaultServiceProvider<ITestService>(_serviceProvider, _configuration, _logger);

            // Act
            var result = provider.UnregisterNamedService("nonexistent");

            // Assert
            Assert.False(result);
        }

        /// <summary>
        /// Tests that provider uses configured default provider.
        /// </summary>
        [Fact]
        public void GetService_WithConfiguredDefaultProvider_UsesConfiguredProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options =>
            {
                options.DefaultProviders[typeof(ITestService).FullName!] = "configured";
            });

            var serviceProvider = services.BuildServiceProvider();
            var configuration = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var logger = serviceProvider.GetRequiredService<ILogger<DefaultServiceProvider<ITestService>>>();

            var provider = new DefaultServiceProvider<ITestService>(serviceProvider, configuration, logger);
            var configuredService = new TestService();
            provider.RegisterNamedService("configured", () => configuredService);

            // Act
            var service = provider.GetService();

            // Assert
            Assert.Same(configuredService, service);
        }
    }

    // Test interfaces and implementations
    public interface ITestService
    {
        string GetData();
    }

    public class TestService : ITestService
    {
        public string GetData() => "Test Data";
    }

    public class AlternativeTestService : ITestService
    {
        public string GetData() => "Alternative Test Data";
    }

    public interface INonExistentService
    {
        void DoSomething();
    }
}