using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Providers;
using S7.Core.Commands.Extensions;
using S7.Infrastructure.Providers;
using Xunit;

namespace S7.Core.Tests.Providers
{
    /// <summary>
    /// Unit tests for ProviderServiceExtensions.
    /// </summary>
    public class ProviderServiceExtensionsTests
    {
        /// <summary>
        /// Tests that AddProviderServices registers core provider services correctly.
        /// </summary>
        [Fact]
        public void AddProviderServices_WithoutConfiguration_RegistersCoreServices()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();

            // Act
            services.AddProviderServices();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            Assert.NotNull(serviceProvider.GetService<IProviderFactory>());
            Assert.NotNull(serviceProvider.GetService<IProviderRegistry>());
            Assert.NotNull(serviceProvider.GetService<IOptionsMonitor<ProviderConfiguration>>());
        }

        /// <summary>
        /// Tests that AddProviderServices with configuration binds options correctly.
        /// </summary>
        [Fact]
        public void AddProviderServices_WithConfiguration_BindsOptions()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();

            var configurationData = new Dictionary<string, string>
            {
                ["Providers:EnableAutoDiscovery"] = "false",
                ["Providers:OperationTimeoutSeconds"] = "60",
                ["Providers:EnableProviderCaching"] = "true"
            };

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configurationData!)
                .Build();

            // Act
            services.AddProviderServices(configuration);
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var providerConfig = options.CurrentValue;

            Assert.False(providerConfig.EnableAutoDiscovery);
            Assert.Equal(60, providerConfig.OperationTimeoutSeconds);
            Assert.True(providerConfig.EnableProviderCaching);
        }

        /// <summary>
        /// Tests that AddSpecializedProviders registers specialized provider types.
        /// </summary>
        [Fact]
        public void AddSpecializedProviders_RegistersSpecializedProviders()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();
            services.Configure<ProviderConfiguration>(options => { });

            // Act
            services.AddSpecializedProviders();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            Assert.NotNull(serviceProvider.GetService<FileSystemProvider<object>>());
            Assert.NotNull(serviceProvider.GetService<MemoryProvider<object>>());
            Assert.NotNull(serviceProvider.GetService<CachingProvider<object>>());
        }

        /// <summary>
        /// Tests that AddS7ProviderServices registers all provider services.
        /// </summary>
        [Fact]
        public void AddS7ProviderServices_RegistersAllServices()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();

            // Act
            services.AddS7ProviderServices();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            // Core services
            Assert.NotNull(serviceProvider.GetService<IProviderFactory>());
            Assert.NotNull(serviceProvider.GetService<IProviderRegistry>());
            
            // Specialized providers
            Assert.NotNull(serviceProvider.GetService<FileSystemProvider<object>>());
            Assert.NotNull(serviceProvider.GetService<MemoryProvider<object>>());
            Assert.NotNull(serviceProvider.GetService<CachingProvider<object>>());
        }

        /// <summary>
        /// Tests that ConfigureProviderOptions configures options correctly.
        /// </summary>
        [Fact]
        public void ConfigureProviderOptions_ConfiguresOptions()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();

            // Act
            services.ConfigureProviderOptions(options =>
            {
                options.EnableAutoDiscovery = false;
                options.OperationTimeoutSeconds = 120;
                options.EnableProviderCaching = false;
            });

            var serviceProvider = services.BuildServiceProvider();

            // Assert
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var providerConfig = options.CurrentValue;

            Assert.False(providerConfig.EnableAutoDiscovery);
            Assert.Equal(120, providerConfig.OperationTimeoutSeconds);
            Assert.False(providerConfig.EnableProviderCaching);
        }

        /// <summary>
        /// Tests that ValidateProviderConfigurations adds validation.
        /// </summary>
        [Fact]
        public void ValidateProviderConfigurations_AddsValidation()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options =>
            {
                options.OperationTimeoutSeconds = -1; // Invalid value
            });

            // Act
            services.ValidateProviderConfigurations();

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            
            // This should throw due to validation
            Assert.Throws<OptionsValidationException>(() =>
            {
                var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
                _ = options.CurrentValue;
            });
        }

        /// <summary>
        /// Tests that AddProviderServicesWithLifetime registers services with custom lifetimes.
        /// </summary>
        [Fact]
        public void AddProviderServicesWithLifetime_RegistersWithCustomLifetimes()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();

            // Act
            services.AddProviderServicesWithLifetime(
                factoryLifetime: Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton,
                registryLifetime: Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton,
                providerLifetime: Microsoft.Extensions.DependencyInjection.ServiceLifetime.Transient);

            var serviceProvider = services.BuildServiceProvider();

            // Assert
            var factory1 = serviceProvider.GetService<IProviderFactory>();
            var factory2 = serviceProvider.GetService<IProviderFactory>();
            Assert.Same(factory1, factory2); // Should be same instance (Singleton)

            var registry1 = serviceProvider.GetService<IProviderRegistry>();
            var registry2 = serviceProvider.GetService<IProviderRegistry>();
            Assert.Same(registry1, registry2); // Should be same instance (Singleton)

            var provider1 = serviceProvider.GetService<FileSystemProvider<object>>();
            var provider2 = serviceProvider.GetService<FileSystemProvider<object>>();
            Assert.NotSame(provider1, provider2); // Should be different instances (Transient)
        }

        /// <summary>
        /// Tests that services can be resolved with generic type parameters.
        /// </summary>
        [Fact]
        public void AddS7ProviderServices_SupportsGenericTypeResolution()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();

            // Act
            services.AddS7ProviderServices();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            Assert.NotNull(serviceProvider.GetService<IServiceProvider<string>>());
            Assert.NotNull(serviceProvider.GetService<FileSystemProvider<string>>());
            Assert.NotNull(serviceProvider.GetService<MemoryProvider<string>>());
            Assert.NotNull(serviceProvider.GetService<CachingProvider<string>>());
        }

        /// <summary>
        /// Tests that multiple calls to AddS7ProviderServices don't cause conflicts.
        /// </summary>
        [Fact]
        public void AddS7ProviderServices_MultipleCallsDoNotConflict()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();

            // Act
            services.AddS7ProviderServices();
            services.AddS7ProviderServices(); // Second call should not cause issues

            var serviceProvider = services.BuildServiceProvider();

            // Assert
            Assert.NotNull(serviceProvider.GetService<IProviderFactory>());
            Assert.NotNull(serviceProvider.GetService<IProviderRegistry>());
        }

        /// <summary>
        /// Tests that configuration validation works with valid values.
        /// </summary>
        [Fact]
        public void ValidateProviderConfigurations_WithValidConfiguration_DoesNotThrow()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();
            services.Configure<ProviderConfiguration>(options =>
            {
                options.OperationTimeoutSeconds = 30; // Valid value
                options.CacheExpirationMinutes = 60; // Valid value
                options.MaxCachedProviders = 100; // Valid value
            });

            // Act
            services.ValidateProviderConfigurations();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var providerConfig = options.CurrentValue; // Should not throw

            Assert.Equal(30, providerConfig.OperationTimeoutSeconds);
            Assert.Equal(60, providerConfig.CacheExpirationMinutes);
            Assert.Equal(100, providerConfig.MaxCachedProviders);
        }

        /// <summary>
        /// Tests that default configuration values are applied correctly.
        /// </summary>
        [Fact]
        public void AddProviderServices_WithoutConfiguration_UsesDefaults()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddLogging();

            // Act
            services.AddProviderServices();
            var serviceProvider = services.BuildServiceProvider();

            // Assert
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProviderConfiguration>>();
            var providerConfig = options.CurrentValue;

            Assert.True(providerConfig.EnableAutoDiscovery);
            Assert.Equal(30, providerConfig.OperationTimeoutSeconds);
            Assert.True(providerConfig.EnableProviderCaching);
            Assert.Equal(60, providerConfig.CacheExpirationMinutes);
            Assert.Equal(100, providerConfig.MaxCachedProviders);
        }
    }
}