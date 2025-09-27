using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Providers
{
    /// <summary>
    /// Defines a registry for discovering, registering, and managing service providers.
    /// </summary>
    /// <remarks>
    /// This registry supports automatic provider discovery, manual registration,
    /// and provider lifecycle management.
    /// </remarks>
    public interface IProviderRegistry
    {
        /// <summary>
        /// Registers a provider factory function with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="factory">The factory function to create the provider.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when factory is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when a provider with the same name is already registered.</exception>
        void RegisterProvider<T>(string name, Func<IDynamicProvider<T>> factory) where T : class;

        /// <summary>
        /// Registers a provider instance with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="provider">The provider instance.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when provider is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when a provider with the same name is already registered.</exception>
        void RegisterProvider<T>(string name, IDynamicProvider<T> provider) where T : class;

        /// <summary>
        /// Registers a provider with metadata.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="factory">The factory function to create the provider.</param>
        /// <param name="metadata">The provider metadata.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when factory or metadata is null.</exception>
        void RegisterProvider<T>(string name, Func<IDynamicProvider<T>> factory, ProviderMetadata metadata) where T : class;

        /// <summary>
        /// Unregisters a provider with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to unregister.</param>
        /// <returns>True if the provider was unregistered; otherwise, false.</returns>
        bool UnregisterProvider<T>(string name) where T : class;

        /// <summary>
        /// Determines whether a provider with the specified name is registered.
        /// </summary>
        /// <typeparam name="T">The type of service to check.</typeparam>
        /// <param name="name">The name of the provider to check.</param>
        /// <returns>True if the provider is registered; otherwise, false.</returns>
        bool IsRegistered<T>(string name) where T : class;

        /// <summary>
        /// Gets the names of all registered providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider names for.</typeparam>
        /// <returns>An enumerable of registered provider names.</returns>
        IEnumerable<string> GetRegisteredNames<T>() where T : class;

        /// <summary>
        /// Gets all registered providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get providers for.</typeparam>
        /// <returns>An enumerable of registered providers with their names.</returns>
        IEnumerable<(string Name, IDynamicProvider<T> Provider)> GetRegisteredProviders<T>() where T : class;

        /// <summary>
        /// Gets a provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <returns>The provider instance, or null if not found.</returns>
        IDynamicProvider<T>? GetProvider<T>(string name) where T : class;

        /// <summary>
        /// Gets a required provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <returns>The provider instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the provider is not found.</exception>
        IDynamicProvider<T> GetRequiredProvider<T>(string name) where T : class;

        /// <summary>
        /// Asynchronously gets a provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        Task<IDynamicProvider<T>?> GetProviderAsync<T>(string name, CancellationToken cancellationToken = default) where T : class;

        /// <summary>
        /// Gets metadata for all registered providers of the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get metadata for.</typeparam>
        /// <returns>An enumerable of provider metadata.</returns>
        IEnumerable<ProviderMetadata> GetProviderMetadata<T>() where T : class;

        /// <summary>
        /// Gets metadata for a specific provider by name.
        /// </summary>
        /// <param name="name">The name of the provider to get metadata for.</param>
        /// <returns>The provider metadata, or null if not found.</returns>
        ProviderMetadata? GetProviderMetadata(string name);

        /// <summary>
        /// Discovers and registers providers from the specified assemblies.
        /// </summary>
        /// <param name="assemblies">The assemblies to scan for providers.</param>
        /// <returns>The number of providers discovered and registered.</returns>
        int DiscoverProviders(params System.Reflection.Assembly[] assemblies);

        /// <summary>
        /// Asynchronously discovers and registers providers from the specified assemblies.
        /// </summary>
        /// <param name="assemblies">The assemblies to scan for providers.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the number of providers discovered.</returns>
        Task<int> DiscoverProvidersAsync(System.Reflection.Assembly[] assemblies, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates all registered providers and their configurations.
        /// </summary>
        /// <returns>A collection of validation results.</returns>
        IEnumerable<ProviderValidationResult> ValidateProviders();

        /// <summary>
        /// Clears all registered providers.
        /// </summary>
        void Clear();

        /// <summary>
        /// Gets the total number of registered providers.
        /// </summary>
        int Count { get; }
    }

    /// <summary>
    /// Represents the result of provider validation.
    /// </summary>
    public class ProviderValidationResult
    {
        /// <summary>
        /// Gets or sets the provider name.
        /// </summary>
        public string ProviderName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the service type.
        /// </summary>
        public Type ServiceType { get; set; } = null!;

        /// <summary>
        /// Gets or sets a value indicating whether the provider is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets the validation error messages.
        /// </summary>
        public List<string> ErrorMessages { get; set; } = new();

        /// <summary>
        /// Gets or sets the validation warning messages.
        /// </summary>
        public List<string> WarningMessages { get; set; } = new();

        /// <summary>
        /// Gets or sets additional validation properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();
    }
}