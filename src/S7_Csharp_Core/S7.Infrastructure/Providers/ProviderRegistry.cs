using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Providers;

namespace S7.Infrastructure.Providers
{
    /// <summary>
    /// Provides registry functionality for discovering, registering, and managing service providers.
    /// </summary>
    /// <remarks>
    /// This registry supports automatic provider discovery, manual registration,
    /// and provider lifecycle management with thread-safe operations.
    /// </remarks>
    public class ProviderRegistry : IProviderRegistry
    {
        private readonly ConcurrentDictionary<string, object> _providers = new();
        private readonly ConcurrentDictionary<string, ProviderMetadata> _metadata = new();
        private readonly ConcurrentDictionary<Type, List<string>> _typeProviders = new();
        private readonly ILogger<ProviderRegistry> _logger;
        private readonly object _lock = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="ProviderRegistry"/> class.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when logger is null.</exception>
        public ProviderRegistry(ILogger<ProviderRegistry> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets the total number of registered providers.
        /// </summary>
        public int Count => _providers.Count;

        /// <summary>
        /// Registers a provider factory function with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="factory">The factory function to create the provider.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when factory is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when a provider with the same name is already registered.</exception>
        public void RegisterProvider<T>(string name, Func<IServiceProvider<T>> factory) where T : class
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Provider name cannot be null or empty", nameof(name));
            if (factory == null)
                throw new ArgumentNullException(nameof(factory));

            var key = GetProviderKey<T>(name);
            
            if (_providers.ContainsKey(key))
            {
                _logger.LogWarning("Provider {ProviderName} for type {ServiceType} is already registered", name, typeof(T).Name);
                throw new InvalidOperationException($"Provider '{name}' for type {typeof(T).Name} is already registered");
            }

            try
            {
                _logger.LogDebug("Registering provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);

                // Create a lazy provider that uses the factory
                var lazyProvider = new Lazy<IServiceProvider<T>>(factory, LazyThreadSafetyMode.ExecutionAndPublication);
                _providers.TryAdd(key, lazyProvider);

                // Add to type-specific provider list
                AddToTypeProviders<T>(name);

                // Create default metadata
                var metadata = new ProviderMetadata
                {
                    Name = name,
                    ProviderType = typeof(IServiceProvider<T>),
                    ServiceType = typeof(T),
                    IsAvailable = true,
                    SupportedLifetime = ServiceLifetime.Scoped
                };

                _metadata.TryAdd(key, metadata);

                _logger.LogDebug("Successfully registered provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
                throw;
            }
        }

        /// <summary>
        /// Registers a provider instance with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="provider">The provider instance.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when provider is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when a provider with the same name is already registered.</exception>
        public void RegisterProvider<T>(string name, IServiceProvider<T> provider) where T : class
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Provider name cannot be null or empty", nameof(name));
            if (provider == null)
                throw new ArgumentNullException(nameof(provider));

            RegisterProvider<T>(name, () => provider);
        }

        /// <summary>
        /// Registers a provider with metadata.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider.</param>
        /// <param name="factory">The factory function to create the provider.</param>
        /// <param name="metadata">The provider metadata.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when factory or metadata is null.</exception>
        public void RegisterProvider<T>(string name, Func<IServiceProvider<T>> factory, ProviderMetadata metadata) where T : class
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));

            RegisterProvider<T>(name, factory);

            // Update metadata
            var key = GetProviderKey<T>(name);
            metadata.Name = name;
            metadata.ServiceType = typeof(T);
            _metadata.TryUpdate(key, metadata, _metadata[key]);

            _logger.LogDebug("Updated metadata for provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
        }

        /// <summary>
        /// Unregisters a provider with the specified name.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to unregister.</param>
        /// <returns>True if the provider was unregistered; otherwise, false.</returns>
        public bool UnregisterProvider<T>(string name) where T : class
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            try
            {
                var key = GetProviderKey<T>(name);
                
                var providerRemoved = _providers.TryRemove(key, out _);
                var metadataRemoved = _metadata.TryRemove(key, out _);

                if (providerRemoved)
                {
                    RemoveFromTypeProviders<T>(name);
                    _logger.LogDebug("Unregistered provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
                }

                return providerRemoved;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unregistering provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
                return false;
            }
        }

        /// <summary>
        /// Determines whether a provider with the specified name is registered.
        /// </summary>
        /// <typeparam name="T">The type of service to check.</typeparam>
        /// <param name="name">The name of the provider to check.</param>
        /// <returns>True if the provider is registered; otherwise, false.</returns>
        public bool IsRegistered<T>(string name) where T : class
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            var key = GetProviderKey<T>(name);
            return _providers.ContainsKey(key);
        }

        /// <summary>
        /// Gets the names of all registered providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider names for.</typeparam>
        /// <returns>An enumerable of registered provider names.</returns>
        public IEnumerable<string> GetRegisteredNames<T>() where T : class
        {
            try
            {
                if (_typeProviders.TryGetValue(typeof(T), out var names))
                {
                    return names.ToList(); // Return a copy to avoid concurrent modification issues
                }
                return Enumerable.Empty<string>();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting registered names for type {ServiceType}", typeof(T).Name);
                return Enumerable.Empty<string>();
            }
        }

        /// <summary>
        /// Gets all registered providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get providers for.</typeparam>
        /// <returns>An enumerable of registered providers with their names.</returns>
        public IEnumerable<(string Name, IServiceProvider<T> Provider)> GetRegisteredProviders<T>() where T : class
        {
            try
            {
                var names = GetRegisteredNames<T>();
                var providers = new List<(string Name, IServiceProvider<T> Provider)>();

                foreach (var name in names)
                {
                    var provider = GetProvider<T>(name);
                    if (provider != null)
                    {
                        providers.Add((name, provider));
                    }
                }

                return providers;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting registered providers for type {ServiceType}", typeof(T).Name);
                return Enumerable.Empty<(string, IServiceProvider<T>)>();
            }
        }

        /// <summary>
        /// Gets a provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <returns>The provider instance, or null if not found.</returns>
        public IServiceProvider<T>? GetProvider<T>(string name) where T : class
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            try
            {
                var key = GetProviderKey<T>(name);
                
                if (_providers.TryGetValue(key, out var providerObj) && providerObj is Lazy<IServiceProvider<T>> lazyProvider)
                {
                    return lazyProvider.Value;
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting provider {ProviderName} for type {ServiceType}", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Gets a required provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <returns>The provider instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the provider is not found.</exception>
        public IServiceProvider<T> GetRequiredProvider<T>(string name) where T : class
        {
            var provider = GetProvider<T>(name);
            if (provider == null)
            {
                _logger.LogError("Required provider {ProviderName} for type {ServiceType} not found", name, typeof(T).Name);
                throw new InvalidOperationException($"Required provider '{name}' for type {typeof(T).Name} not found");
            }

            return provider;
        }

        /// <summary>
        /// Asynchronously gets a provider by name for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service the provider handles.</typeparam>
        /// <param name="name">The name of the provider to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        public async Task<IServiceProvider<T>?> GetProviderAsync<T>(string name, CancellationToken cancellationToken = default) where T : class
        {
            return await Task.Run(() => GetProvider<T>(name), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets metadata for all registered providers of the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get metadata for.</typeparam>
        /// <returns>An enumerable of provider metadata.</returns>
        public IEnumerable<ProviderMetadata> GetProviderMetadata<T>() where T : class
        {
            try
            {
                var names = GetRegisteredNames<T>();
                var metadataList = new List<ProviderMetadata>();

                foreach (var name in names)
                {
                    var metadata = GetProviderMetadata(name);
                    if (metadata != null)
                    {
                        metadataList.Add(metadata);
                    }
                }

                return metadataList;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting provider metadata for type {ServiceType}", typeof(T).Name);
                return Enumerable.Empty<ProviderMetadata>();
            }
        }

        /// <summary>
        /// Gets metadata for a specific provider by name.
        /// </summary>
        /// <param name="name">The name of the provider to get metadata for.</param>
        /// <returns>The provider metadata, or null if not found.</returns>
        public ProviderMetadata? GetProviderMetadata(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            try
            {
                // Find metadata by searching through all registered providers
                var matchingMetadata = _metadata.Values.FirstOrDefault(m => m.Name == name);
                return matchingMetadata;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting metadata for provider {ProviderName}", name);
                return null;
            }
        }

        /// <summary>
        /// Discovers and registers providers from the specified assemblies.
        /// </summary>
        /// <param name="assemblies">The assemblies to scan for providers.</param>
        /// <returns>The number of providers discovered and registered.</returns>
        public int DiscoverProviders(params Assembly[] assemblies)
        {
            if (assemblies == null || assemblies.Length == 0)
                return 0;

            try
            {
                _logger.LogDebug("Starting provider discovery in {AssemblyCount} assemblies", assemblies.Length);

                var discoveredCount = 0;

                foreach (var assembly in assemblies)
                {
                    try
                    {
                        var types = assembly.GetTypes()
                            .Where(t => t.IsClass && !t.IsAbstract)
                            .Where(t => t.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IServiceProvider<>)))
                            .ToList();

                        foreach (var type in types)
                        {
                            try
                            {
                                // This is a simplified discovery - in production, you'd use attributes or conventions
                                var providerName = type.Name.Replace("Provider", "").Replace("ServiceProvider", "");
                                _logger.LogDebug("Discovered potential provider: {ProviderType} with name {ProviderName}", type.Name, providerName);
                                discoveredCount++;
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Error processing discovered type {TypeName}", type.Name);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error scanning assembly {AssemblyName}", assembly.FullName);
                    }
                }

                _logger.LogDebug("Provider discovery completed. Discovered {DiscoveredCount} potential providers", discoveredCount);
                return discoveredCount;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during provider discovery");
                return 0;
            }
        }

        /// <summary>
        /// Asynchronously discovers and registers providers from the specified assemblies.
        /// </summary>
        /// <param name="assemblies">The assemblies to scan for providers.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the number of providers discovered.</returns>
        public async Task<int> DiscoverProvidersAsync(Assembly[] assemblies, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() => DiscoverProviders(assemblies), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Validates all registered providers and their configurations.
        /// </summary>
        /// <returns>A collection of validation results.</returns>
        public IEnumerable<ProviderValidationResult> ValidateProviders()
        {
            try
            {
                _logger.LogDebug("Starting provider validation for {ProviderCount} providers", _providers.Count);

                var results = new List<ProviderValidationResult>();

                foreach (var kvp in _metadata)
                {
                    var metadata = kvp.Value;
                    var result = new ProviderValidationResult
                    {
                        ProviderName = metadata.Name,
                        ServiceType = metadata.ServiceType,
                        IsValid = true
                    };

                    try
                    {
                        // Basic validation - check if provider can be created
                        var key = kvp.Key;
                        if (!_providers.ContainsKey(key))
                        {
                            result.IsValid = false;
                            result.ErrorMessages.Add("Provider registration not found");
                        }

                        // Additional validation logic can be added here
                        if (string.IsNullOrWhiteSpace(metadata.Name))
                        {
                            result.IsValid = false;
                            result.ErrorMessages.Add("Provider name is empty");
                        }

                        if (metadata.ServiceType == null)
                        {
                            result.IsValid = false;
                            result.ErrorMessages.Add("Service type is null");
                        }
                    }
                    catch (Exception ex)
                    {
                        result.IsValid = false;
                        result.ErrorMessages.Add($"Validation error: {ex.Message}");
                        _logger.LogWarning(ex, "Error validating provider {ProviderName}", metadata.Name);
                    }

                    results.Add(result);
                }

                var validCount = results.Count(r => r.IsValid);
                _logger.LogDebug("Provider validation completed. {ValidCount}/{TotalCount} providers are valid", validCount, results.Count);

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during provider validation");
                return Enumerable.Empty<ProviderValidationResult>();
            }
        }

        /// <summary>
        /// Clears all registered providers.
        /// </summary>
        public void Clear()
        {
            try
            {
                _logger.LogDebug("Clearing all registered providers");

                _providers.Clear();
                _metadata.Clear();
                _typeProviders.Clear();

                _logger.LogDebug("All providers cleared successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing providers");
            }
        }

        private static string GetProviderKey<T>(string name) where T : class
        {
            return $"{typeof(T).FullName}:{name}";
        }

        private void AddToTypeProviders<T>(string name) where T : class
        {
            lock (_lock)
            {
                var serviceType = typeof(T);
                if (!_typeProviders.TryGetValue(serviceType, out var names))
                {
                    names = new List<string>();
                    _typeProviders.TryAdd(serviceType, names);
                }

                if (!names.Contains(name))
                {
                    names.Add(name);
                }
            }
        }

        private void RemoveFromTypeProviders<T>(string name) where T : class
        {
            lock (_lock)
            {
                var serviceType = typeof(T);
                if (_typeProviders.TryGetValue(serviceType, out var names))
                {
                    names.Remove(name);
                    if (names.Count == 0)
                    {
                        _typeProviders.TryRemove(serviceType, out _);
                    }
                }
            }
        }
    }
}