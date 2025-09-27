using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Providers;
using S7.Infrastructure.Providers;

namespace S7.Core.Commands.Extensions
{
    /// <summary>
    /// Extension methods for registering provider services in the dependency injection container.
    /// </summary>
    public static class ProviderServiceExtensions
    {
        /// <summary>
        /// Adds provider services to the service collection with default configuration.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddProviderServices(this IServiceCollection services)
        {
            return services.AddProviderServices(configuration: null);
        }

        /// <summary>
        /// Adds provider services to the service collection with configuration support.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddProviderServices(
            this IServiceCollection services,
            IConfiguration? configuration)
        {
            // Register configuration options
            if (configuration != null)
            {
                services.Configure<ProviderConfiguration>(options =>
                    configuration.GetSection(ProviderConfiguration.SectionName).Bind(options));
            }
            else
            {
                // Use default configuration
                services.Configure<ProviderConfiguration>(options => { });
            }

            // Register core provider services
            services.TryAddScoped<IProviderFactory, DynamicProviderFactory>();
            services.TryAddSingleton<IProviderRegistry, ProviderRegistry>();
            services.TryAddScoped(typeof(IDynamicProvider<>), typeof(DefaultServiceProvider<>));

            return services;
        }

        /// <summary>
        /// Adds specialized provider implementations to the service collection.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddSpecializedProviders(this IServiceCollection services)
        {
            // Register specialized provider implementations as generic types
            services.TryAddScoped(typeof(FileSystemProvider<>));
            services.TryAddScoped(typeof(MemoryProvider<>));
            services.TryAddScoped(typeof(CachingProvider<>));

            return services;
        }

        /// <summary>
        /// Adds all provider services to the service collection.
        /// This is a convenience method that registers both core and specialized provider services.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddS7ProviderServices(
            this IServiceCollection services,
            IConfiguration? configuration = null)
        {
            return services
                .AddProviderServices(configuration)
                .AddSpecializedProviders();
        }

        /// <summary>
        /// Configures provider options using a delegate.
        /// </summary>
        /// <param name="services">The service collection to configure.</param>
        /// <param name="configureProvider">Configuration delegate for provider options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection ConfigureProviderOptions(
            this IServiceCollection services,
            Action<ProviderConfiguration>? configureProvider = null)
        {
            if (configureProvider != null)
            {
                services.Configure(configureProvider);
            }

            return services;
        }

        /// <summary>
        /// Validates provider configurations at startup.
        /// </summary>
        /// <param name="services">The service collection to validate.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection ValidateProviderConfigurations(this IServiceCollection services)
        {
            // Add validation for configuration options
            services.AddOptions<ProviderConfiguration>()
                .ValidateDataAnnotations()
                .ValidateOnStart();

            return services;
        }

        /// <summary>
        /// Adds provider services with custom lifetime management.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="factoryLifetime">The lifetime for provider factory services.</param>
        /// <param name="registryLifetime">The lifetime for provider registry services.</param>
        /// <param name="providerLifetime">The lifetime for provider services.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddProviderServicesWithLifetime(
            this IServiceCollection services,
            Microsoft.Extensions.DependencyInjection.ServiceLifetime factoryLifetime = Microsoft.Extensions.DependencyInjection.ServiceLifetime.Scoped,
            Microsoft.Extensions.DependencyInjection.ServiceLifetime registryLifetime = Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton,
            Microsoft.Extensions.DependencyInjection.ServiceLifetime providerLifetime = Microsoft.Extensions.DependencyInjection.ServiceLifetime.Scoped,
            IConfiguration? configuration = null)
        {
            // Register configuration options
            if (configuration != null)
            {
                services.Configure<ProviderConfiguration>(options =>
                    configuration.GetSection(ProviderConfiguration.SectionName).Bind(options));
            }

            // Register provider services with specified lifetimes
            services.Add(ServiceDescriptor.Describe(typeof(IProviderFactory), typeof(DynamicProviderFactory), factoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IProviderRegistry), typeof(ProviderRegistry), registryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IDynamicProvider<>), typeof(DefaultServiceProvider<>), providerLifetime));

            // Register specialized providers with specified lifetime
            services.Add(ServiceDescriptor.Describe(typeof(FileSystemProvider<>), typeof(FileSystemProvider<>), providerLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(MemoryProvider<>), typeof(MemoryProvider<>), providerLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(CachingProvider<>), typeof(CachingProvider<>), providerLifetime));

            return services;
        }
    }
}