using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using S7.Core.Abstractions.Configuration;

namespace S7.Core.Abstractions.Providers
{
    /// <summary>
    /// Provides factory methods for creating dynamic provider instances with dependency injection support.
    /// </summary>
    /// <remarks>
    /// This factory supports configuration-driven provider selection and integrates with
    /// the Microsoft.Extensions.DependencyInjection container.
    /// </remarks>
    public interface IProviderFactory
    {
        /// <summary>
        /// Creates a dynamic provider for the specified type using the default configuration.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <returns>A configured dynamic provider instance.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the provider cannot be created due to configuration issues.
        /// </exception>
        IDynamicProvider<T> CreateProvider<T>() where T : class;

        /// <summary>
        /// Creates a dynamic provider for the specified type using the provided configuration.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="configuration">The provider configuration to use.</param>
        /// <returns>A configured dynamic provider instance.</returns>
        /// <exception cref="ArgumentNullException">Thrown when configuration is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the provider cannot be created due to configuration issues.
        /// </exception>
        IDynamicProvider<T> CreateProvider<T>(ProviderConfiguration configuration) where T : class;

        /// <summary>
        /// Creates a dynamic provider for the specified type with a specific name.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="providerName">The name of the provider to create.</param>
        /// <returns>A configured dynamic provider instance.</returns>
        /// <exception cref="ArgumentException">Thrown when providerName is null or empty.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the provider cannot be created.
        /// </exception>
        IDynamicProvider<T> CreateProvider<T>(string providerName) where T : class;

        /// <summary>
        /// Asynchronously creates a dynamic provider for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        Task<IDynamicProvider<T>> CreateProviderAsync<T>(CancellationToken cancellationToken = default) where T : class;

        /// <summary>
        /// Asynchronously creates a dynamic provider for the specified type using the provided configuration.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="configuration">The provider configuration to use.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        Task<IDynamicProvider<T>> CreateProviderAsync<T>(ProviderConfiguration configuration, CancellationToken cancellationToken = default) where T : class;

        /// <summary>
        /// Determines whether a provider can be created for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to check.</typeparam>
        /// <returns>True if a provider can be created; otherwise, false.</returns>
        bool CanCreateProvider<T>() where T : class;

        /// <summary>
        /// Determines whether a provider with the specified name can be created.
        /// </summary>
        /// <param name="providerName">The name of the provider to check.</param>
        /// <returns>True if the provider can be created; otherwise, false.</returns>
        bool CanCreateProvider(string providerName);

        /// <summary>
        /// Gets the names of all available providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider names for.</typeparam>
        /// <returns>An enumerable of provider names.</returns>
        IEnumerable<string> GetAvailableProviderNames<T>() where T : class;

        /// <summary>
        /// Gets metadata about all available providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider metadata for.</typeparam>
        /// <returns>An enumerable of provider metadata.</returns>
        IEnumerable<ProviderMetadata> GetProviderMetadata<T>() where T : class;

        /// <summary>
        /// Gets metadata for a specific provider by name.
        /// </summary>
        /// <param name="providerName">The name of the provider to get metadata for.</param>
        /// <returns>The provider metadata, or null if not found.</returns>
        ProviderMetadata? GetProviderMetadata(string providerName);
    }

    /// <summary>
    /// Represents metadata about a provider registration.
    /// </summary>
    public class ProviderMetadata
    {
        /// <summary>
        /// Gets or sets the provider name.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the provider type.
        /// </summary>
        public Type ProviderType { get; set; } = null!;

        /// <summary>
        /// Gets or sets the service type that this provider handles.
        /// </summary>
        public Type ServiceType { get; set; } = null!;

        /// <summary>
        /// Gets or sets the provider description.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets the provider version.
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the provider priority for selection.
        /// </summary>
        public int Priority { get; set; } = 0;

        /// <summary>
        /// Gets or sets a value indicating whether the provider is available.
        /// </summary>
        public bool IsAvailable { get; set; } = true;

        /// <summary>
        /// Gets or sets additional metadata properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();

        /// <summary>
        /// Gets or sets the supported service lifetime.
        /// </summary>
        public ServiceLifetime SupportedLifetime { get; set; } = ServiceLifetime.Scoped;

        /// <summary>
        /// Gets or sets the configuration requirements for this provider.
        /// </summary>
        public List<string> RequiredConfigurationKeys { get; set; } = new();
    }
}