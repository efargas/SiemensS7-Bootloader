using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Factories;
using S7.Core.Abstractions.Repositories;
using S7.Infrastructure.Factories;
using S7.Infrastructure.Repositories;
using S7.Services.Configuration;
using S7.Services.Interfaces;
using S7.Services;

namespace S7.Core.Commands.Extensions
{
    /// <summary>
    /// Extension methods for registering factory services in the dependency injection container.
    /// </summary>
    public static class FactoryServiceExtensions
    {
        /// <summary>
        /// Adds factory services to the service collection with default configuration.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddFactoryServices(this IServiceCollection services)
        {
            return services.AddFactoryServices(configuration: null);
        }

        /// <summary>
        /// Adds factory services to the service collection with configuration support.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddFactoryServices(
            this IServiceCollection services,
            IConfiguration? configuration)
        {
            // Register configuration options
            if (configuration != null)
            {
                var virtualFileReaderSection = configuration.GetSection(VirtualFileReaderConfiguration.SectionName);
                var repositoryFactorySection = configuration.GetSection(RepositoryFactoryConfiguration.SectionName);
                var abstractFactorySection = configuration.GetSection(AbstractFactoryConfiguration.SectionName);

                services.Configure<VirtualFileReaderConfiguration>(virtualFileReaderSection);
                services.Configure<RepositoryFactoryConfiguration>(repositoryFactorySection);
                services.Configure<AbstractFactoryConfiguration>(abstractFactorySection);
            }
            else
            {
                // Use default configurations
                services.Configure<VirtualFileReaderConfiguration>(options => { });
                services.Configure<RepositoryFactoryConfiguration>(options => { });
                services.Configure<AbstractFactoryConfiguration>(options => { });
            }

            // Register virtual file reader factory
            services.TryAddScoped<IVirtualFileReaderFactory, VirtualFileReaderFactory>();

            // Register repository factory
            services.TryAddScoped<IRepositoryFactory, RepositoryFactory>();

            // Register abstract factories
            services.TryAddScoped<IAbstractFactory<IRepositoryFactory>, AbstractRepositoryFactory>();
            services.TryAddScoped<IAbstractFactory<IFileRepository, RepositoryImplementationType>, FileRepositoryAbstractFactory>();
            services.TryAddScoped<IAbstractFactory<IMemoryDumpRepository, RepositoryImplementationType>, MemoryDumpRepositoryAbstractFactory>();
            services.TryAddScoped<IAbstractFactory<IUnitOfWork, bool, int>, UnitOfWorkAbstractFactory>();

            return services;
        }

        /// <summary>
        /// Adds repository services to the service collection.
        /// This method registers the concrete repository implementations that factories depend on.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddRepositoryServices(this IServiceCollection services)
        {
            // Register repository implementations
            services.TryAddScoped<FileRepository>();
            services.TryAddScoped<MemoryDumpRepository>();
            services.TryAddScoped<FileUnitOfWork>();

            // Register repository interfaces
            services.TryAddScoped<IFileRepository>(provider => provider.GetRequiredService<FileRepository>());
            services.TryAddScoped<IMemoryDumpRepository>(provider => provider.GetRequiredService<MemoryDumpRepository>());
            services.TryAddScoped<IUnitOfWork>(provider => provider.GetRequiredService<FileUnitOfWork>());

            return services;
        }

        /// <summary>
        /// Adds all factory and repository services to the service collection.
        /// This is a convenience method that registers both factory and repository services.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddS7FactoryServices(
            this IServiceCollection services,
            IConfiguration? configuration = null)
        {
            return services
                .AddRepositoryServices()
                .AddFactoryServices(configuration);
        }

        /// <summary>
        /// Configures factory options using a delegate.
        /// </summary>
        /// <param name="services">The service collection to configure.</param>
        /// <param name="configureVirtualFileReader">Configuration delegate for virtual file reader options.</param>
        /// <param name="configureRepositoryFactory">Configuration delegate for repository factory options.</param>
        /// <param name="configureAbstractFactory">Configuration delegate for abstract factory options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection ConfigureFactoryOptions(
            this IServiceCollection services,
            Action<VirtualFileReaderConfiguration>? configureVirtualFileReader = null,
            Action<RepositoryFactoryConfiguration>? configureRepositoryFactory = null,
            Action<AbstractFactoryConfiguration>? configureAbstractFactory = null)
        {
            if (configureVirtualFileReader != null)
            {
                services.Configure(configureVirtualFileReader);
            }

            if (configureRepositoryFactory != null)
            {
                services.Configure(configureRepositoryFactory);
            }

            if (configureAbstractFactory != null)
            {
                services.Configure(configureAbstractFactory);
            }

            return services;
        }

        /// <summary>
        /// Validates factory configurations at startup.
        /// </summary>
        /// <param name="services">The service collection to validate.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection ValidateFactoryConfigurations(this IServiceCollection services)
        {
            // Add validation for configuration options
            services.AddOptions<VirtualFileReaderConfiguration>()
                .ValidateDataAnnotations()
                .ValidateOnStart();

            services.AddOptions<RepositoryFactoryConfiguration>()
                .ValidateDataAnnotations()
                .ValidateOnStart();

            services.AddOptions<AbstractFactoryConfiguration>()
                .ValidateDataAnnotations()
                .ValidateOnStart();

            return services;
        }

        /// <summary>
        /// Adds factory services with custom lifetime management.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <param name="factoryLifetime">The lifetime for factory services.</param>
        /// <param name="repositoryLifetime">The lifetime for repository services.</param>
        /// <param name="configuration">The configuration instance for binding options.</param>
        /// <returns>The service collection for chaining.</returns>
        public static IServiceCollection AddFactoryServicesWithLifetime(
            this IServiceCollection services,
            ServiceLifetime factoryLifetime = ServiceLifetime.Scoped,
            ServiceLifetime repositoryLifetime = ServiceLifetime.Scoped,
            IConfiguration? configuration = null)
        {
            // Register configuration options
            if (configuration != null)
            {
                var virtualFileReaderSection = configuration.GetSection(VirtualFileReaderConfiguration.SectionName);
                var repositoryFactorySection = configuration.GetSection(RepositoryFactoryConfiguration.SectionName);
                var abstractFactorySection = configuration.GetSection(AbstractFactoryConfiguration.SectionName);

                services.Configure<VirtualFileReaderConfiguration>(virtualFileReaderSection);
                services.Configure<RepositoryFactoryConfiguration>(repositoryFactorySection);
                services.Configure<AbstractFactoryConfiguration>(abstractFactorySection);
            }

            // Register factories with specified lifetime
            services.Add(ServiceDescriptor.Describe(typeof(IVirtualFileReaderFactory), typeof(VirtualFileReaderFactory), factoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IRepositoryFactory), typeof(RepositoryFactory), factoryLifetime));

            // Register abstract factories with specified lifetime
            services.Add(ServiceDescriptor.Describe(typeof(IAbstractFactory<IRepositoryFactory>), typeof(AbstractRepositoryFactory), factoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IAbstractFactory<IFileRepository, RepositoryImplementationType>), typeof(FileRepositoryAbstractFactory), factoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IAbstractFactory<IMemoryDumpRepository, RepositoryImplementationType>), typeof(MemoryDumpRepositoryAbstractFactory), factoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IAbstractFactory<IUnitOfWork, bool, int>), typeof(UnitOfWorkAbstractFactory), factoryLifetime));

            // Register repositories with specified lifetime
            services.Add(ServiceDescriptor.Describe(typeof(FileRepository), typeof(FileRepository), repositoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(MemoryDumpRepository), typeof(MemoryDumpRepository), repositoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(FileUnitOfWork), typeof(FileUnitOfWork), repositoryLifetime));

            // Register repository interfaces
            services.Add(ServiceDescriptor.Describe(typeof(IFileRepository), provider => provider.GetRequiredService<FileRepository>(), repositoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IMemoryDumpRepository), provider => provider.GetRequiredService<MemoryDumpRepository>(), repositoryLifetime));
            services.Add(ServiceDescriptor.Describe(typeof(IUnitOfWork), provider => provider.GetRequiredService<FileUnitOfWork>(), repositoryLifetime));

            return services;
        }
    }
}