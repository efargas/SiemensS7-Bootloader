using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Providers;

namespace S7.Infrastructure.Providers
{
    /// <summary>
    /// Provides factory methods for creating dynamic provider instances with dependency injection support.
    /// </summary>
    /// <remarks>
    /// This factory supports configuration-driven provider selection and integrates with
    /// the Microsoft.Extensions.DependencyInjection container.
    /// </remarks>
    public class DynamicProviderFactory(
        IServiceProvider serviceProvider,
        IProviderRegistry providerRegistry,
        IOptionsMonitor<ProviderConfiguration> configuration,
        ILogger<DynamicProviderFactory> logger) : IProviderFactory
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        private readonly IProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        private readonly ILogger<DynamicProviderFactory> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        /// <summary>
        /// Creates a dynamic provider for the specified type using the default configuration.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <returns>A configured dynamic provider instance.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the provider cannot be created due to configuration issues.
        /// </exception>
        public IDynamicProvider<T> CreateProvider<T>() where T : class
        {
            try
            {
                _logger.LogDebug("Creating provider for type {ServiceType}", typeof(T).Name);

                var config = _configuration.CurrentValue;
                var serviceTypeName = typeof(T).FullName ?? typeof(T).Name;

                // Check if there's a default provider configured for this type
                if (config.DefaultProviders.TryGetValue(serviceTypeName, out var defaultProviderName))
                {
                    _logger.LogDebug("Using configured default provider {ProviderName} for type {ServiceType}",
                        defaultProviderName, typeof(T).Name);
                    return CreateProvider<T>(defaultProviderName);
                }

                // Use selection strategy to choose a provider
                var availableProviders = _providerRegistry.GetRegisteredNames<T>().ToList();
                if (!availableProviders.Any())
                {
                    _logger.LogWarning("No providers registered for type {ServiceType}", typeof(T).Name);
                    throw new InvalidOperationException($"No providers registered for type {typeof(T).Name}");
                }

                var selectedProvider = SelectProvider<T>(availableProviders, config.DefaultSelectionStrategy);
                _logger.LogDebug("Selected provider {ProviderName} for type {ServiceType} using strategy {Strategy}",
                    selectedProvider, typeof(T).Name, config.DefaultSelectionStrategy);

                return CreateProvider<T>(selectedProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create provider for type {ServiceType}", typeof(T).Name);
                throw new InvalidOperationException($"Failed to create provider for type {typeof(T).Name}", ex);
            }
        }

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
        public IDynamicProvider<T> CreateProvider<T>(ProviderConfiguration configuration) where T : class
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            try
            {
                _logger.LogDebug("Creating provider for type {ServiceType} with custom configuration", typeof(T).Name);

                var serviceTypeName = typeof(T).FullName ?? typeof(T).Name;

                // Check if there's a default provider configured for this type in the custom config
                if (configuration.DefaultProviders.TryGetValue(serviceTypeName, out var defaultProviderName))
                {
                    return CreateProvider<T>(defaultProviderName);
                }

                // Use selection strategy from custom configuration
                var availableProviders = _providerRegistry.GetRegisteredNames<T>().ToList();
                if (!availableProviders.Any())
                {
                    throw new InvalidOperationException($"No providers registered for type {typeof(T).Name}");
                }

                var selectedProvider = SelectProvider<T>(availableProviders, configuration.DefaultSelectionStrategy);
                return CreateProvider<T>(selectedProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create provider for type {ServiceType} with custom configuration", typeof(T).Name);
                throw new InvalidOperationException($"Failed to create provider for type {typeof(T).Name} with custom configuration", ex);
            }
        }

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
        public IDynamicProvider<T> CreateProvider<T>(string providerName) where T : class
        {
            if (string.IsNullOrWhiteSpace(providerName))
                throw new ArgumentException("Provider name cannot be null or empty", nameof(providerName));

            try
            {
                _logger.LogDebug("Creating provider {ProviderName} for type {ServiceType}", providerName, typeof(T).Name);

                var provider = _providerRegistry.GetProvider<T>(providerName);
                if (provider == null)
                {
                    _logger.LogWarning("Provider {ProviderName} not found for type {ServiceType}", providerName, typeof(T).Name);
                    throw new InvalidOperationException($"Provider '{providerName}' not found for type {typeof(T).Name}");
                }

                _logger.LogDebug("Successfully created provider {ProviderName} for type {ServiceType}", providerName, typeof(T).Name);
                return provider;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create provider {ProviderName} for type {ServiceType}", providerName, typeof(T).Name);
                throw new InvalidOperationException($"Failed to create provider '{providerName}' for type {typeof(T).Name}", ex);
            }
        }

        /// <summary>
        /// Asynchronously creates a dynamic provider for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        public async Task<IDynamicProvider<T>> CreateProviderAsync<T>(CancellationToken cancellationToken = default) where T : class
        {
            return await Task.Run(() => CreateProvider<T>(), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Asynchronously creates a dynamic provider for the specified type using the provided configuration.
        /// </summary>
        /// <typeparam name="T">The type of service to provide.</typeparam>
        /// <param name="configuration">The provider configuration to use.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the provider instance.</returns>
        public async Task<IDynamicProvider<T>> CreateProviderAsync<T>(ProviderConfiguration configuration, CancellationToken cancellationToken = default) where T : class
        {
            return await Task.Run(() => CreateProvider<T>(configuration), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Determines whether a provider can be created for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to check.</typeparam>
        /// <returns>True if a provider can be created; otherwise, false.</returns>
        public bool CanCreateProvider<T>() where T : class
        {
            try
            {
                var availableProviders = _providerRegistry.GetRegisteredNames<T>();
                return availableProviders.Any();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking if provider can be created for type {ServiceType}", typeof(T).Name);
                return false;
            }
        }

        /// <summary>
        /// Determines whether a provider with the specified name can be created.
        /// </summary>
        /// <param name="providerName">The name of the provider to check.</param>
        /// <returns>True if the provider can be created; otherwise, false.</returns>
        public bool CanCreateProvider(string providerName)
        {
            if (string.IsNullOrWhiteSpace(providerName))
                return false;

            try
            {
                var metadata = _providerRegistry.GetProviderMetadata(providerName);
                return metadata?.IsAvailable == true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking if provider {ProviderName} can be created", providerName);
                return false;
            }
        }

        /// <summary>
        /// Gets the names of all available providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider names for.</typeparam>
        /// <returns>An enumerable of provider names.</returns>
        public IEnumerable<string> GetAvailableProviderNames<T>() where T : class
        {
            try
            {
                return _providerRegistry.GetRegisteredNames<T>();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting available provider names for type {ServiceType}", typeof(T).Name);
                return Enumerable.Empty<string>();
            }
        }

        /// <summary>
        /// Gets metadata about all available providers for the specified type.
        /// </summary>
        /// <typeparam name="T">The type of service to get provider metadata for.</typeparam>
        /// <returns>An enumerable of provider metadata.</returns>
        public IEnumerable<ProviderMetadata> GetProviderMetadata<T>() where T : class
        {
            try
            {
                return _providerRegistry.GetProviderMetadata<T>();
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
        /// <param name="providerName">The name of the provider to get metadata for.</param>
        /// <returns>The provider metadata, or null if not found.</returns>
        public ProviderMetadata? GetProviderMetadata(string providerName)
        {
            if (string.IsNullOrWhiteSpace(providerName))
                return null;

            try
            {
                return _providerRegistry.GetProviderMetadata(providerName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting metadata for provider {ProviderName}", providerName);
                return null;
            }
        }

        private string SelectProvider<T>(IList<string> availableProviders, ProviderSelectionStrategy strategy) where T : class
        {
            if (!availableProviders.Any())
                throw new InvalidOperationException("No providers available for selection");

            return strategy switch
            {
                ProviderSelectionStrategy.FirstAvailable => availableProviders.First(),
                ProviderSelectionStrategy.HighestPriority => SelectByPriority<T>(availableProviders, true),
                ProviderSelectionStrategy.LowestPriority => SelectByPriority<T>(availableProviders, false),
                ProviderSelectionStrategy.Random => SelectRandom(availableProviders),
                ProviderSelectionStrategy.RoundRobin => SelectRoundRobin<T>(availableProviders),
                ProviderSelectionStrategy.LoadBalanced => SelectLoadBalanced<T>(availableProviders),
                ProviderSelectionStrategy.Custom => SelectCustom<T>(availableProviders),
                _ => availableProviders.First()
            };
        }

        private string SelectByPriority<T>(IList<string> availableProviders, bool highest) where T : class
        {
            var providersWithMetadata = availableProviders
                .Select(name => new { Name = name, Metadata = _providerRegistry.GetProviderMetadata(name) })
                .Where(p => p.Metadata != null)
                .ToList();

            if (!providersWithMetadata.Any())
                return availableProviders.First();

            var selected = highest
                ? providersWithMetadata.OrderByDescending(p => p.Metadata!.Priority).First()
                : providersWithMetadata.OrderBy(p => p.Metadata!.Priority).First();

            return selected.Name;
        }

        private static string SelectRandom(IList<string> availableProviders)
        {
            var random = new Random();
            var index = random.Next(availableProviders.Count);
            return availableProviders[index];
        }

        private string SelectRoundRobin<T>(IList<string> availableProviders) where T : class
        {
            // Simple round-robin implementation - in production, this would use a more sophisticated approach
            var serviceTypeName = typeof(T).FullName ?? typeof(T).Name;
            var key = $"RoundRobin_{serviceTypeName}";

            // This is a simplified implementation - in production, you'd use a proper state management approach
            var index = Math.Abs(key.GetHashCode()) % availableProviders.Count;
            return availableProviders[index];
        }

        private string SelectLoadBalanced<T>(IList<string> availableProviders) where T : class
        {
            // Simplified load balancing - select the first available provider
            // In production, this would consider actual load metrics
            return availableProviders.First();
        }

        private string SelectCustom<T>(IList<string> availableProviders) where T : class
        {
            // Custom selection logic - for now, just return the first available
            // This could be extended to support custom selection delegates
            return availableProviders.First();
        }
    }
}