using System;
using System.Collections.Concurrent;
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
    /// Provides an in-memory implementation of the service provider pattern with high-performance caching.
    /// </summary>
    /// <typeparam name="T">The type of service this provider handles.</typeparam>
    /// <remarks>
    /// This provider stores all service configurations and instances in memory for fast access.
    /// It supports concurrent operations and provides excellent performance for frequently accessed services.
    /// </remarks>
    public class MemoryProvider<T> : IServiceProvider<T> where T : class
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<MemoryProvider<T>> _logger;
        private readonly ConcurrentDictionary<string, Func<T>> _namedServices = new();
        private readonly ConcurrentDictionary<string, ServiceMetadata<T>> _serviceMetadata = new();
        private readonly ConcurrentDictionary<string, T> _serviceInstances = new();
        private readonly ConcurrentDictionary<string, DateTime> _instanceCreationTimes = new();
        private readonly Timer _cleanupTimer;
        private readonly object _defaultServiceLock = new();
        private T? _defaultServiceInstance;
        private DateTime _defaultServiceCreationTime;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryProvider{T}"/> class.
        /// </summary>
        /// <param name="serviceProvider">The dependency injection service provider.</param>
        /// <param name="configuration">The provider configuration options.</param>
        /// <param name="logger">The logger instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public MemoryProvider(
            IServiceProvider serviceProvider,
            IOptionsMonitor<ProviderConfiguration> configuration,
            ILogger<MemoryProvider<T>> logger)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Initialize cleanup timer for cache expiration
            _cleanupTimer = new Timer(CleanupExpiredServices, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            InitializeDefaultServices();
        }

        /// <summary>
        /// Gets a service instance using the default configuration.
        /// </summary>
        /// <returns>The service instance, or null if not available.</returns>
        public T? GetService()
        {
            try
            {
                _logger.LogDebug("Getting default service for type {ServiceType} from memory provider", typeof(T).Name);

                var config = _configuration.CurrentValue;

                // Check if caching is enabled and we have a cached instance
                if (config.EnableProviderCaching)
                {
                    lock (_defaultServiceLock)
                    {
                        if (_defaultServiceInstance != null && !IsInstanceExpired(_defaultServiceCreationTime, config))
                        {
                            _logger.LogDebug("Retrieved cached default service for type {ServiceType}", typeof(T).Name);
                            return _defaultServiceInstance;
                        }
                    }
                }

                // Try to get from DI container
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                {
                    if (config.EnableProviderCaching)
                    {
                        lock (_defaultServiceLock)
                        {
                            _defaultServiceInstance = service;
                            _defaultServiceCreationTime = DateTime.UtcNow;
                        }
                    }

                    _logger.LogDebug("Retrieved service from DI container for type {ServiceType}", typeof(T).Name);
                    return service;
                }

                // Try to get from named services
                var serviceTypeName = typeof(T).FullName ?? typeof(T).Name;
                if (config.DefaultProviders.TryGetValue(serviceTypeName, out var defaultProviderName))
                {
                    _logger.LogDebug("Using configured default provider {ProviderName} for type {ServiceType}", 
                        defaultProviderName, typeof(T).Name);
                    return GetService(defaultProviderName);
                }

                // Return the first available named service
                var firstService = _namedServices.Values.FirstOrDefault();
                if (firstService != null)
                {
                    var instance = firstService();
                    _logger.LogDebug("Using first available memory service for type {ServiceType}", typeof(T).Name);
                    return instance;
                }

                _logger.LogWarning("No memory service available for type {ServiceType}", typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting default service for type {ServiceType} from memory provider", typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Gets a service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <returns>The service instance, or null if not found.</returns>
        public T? GetService(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return GetService();

            try
            {
                _logger.LogDebug("Getting named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);

                var config = _configuration.CurrentValue;

                // Check if caching is enabled and we have a cached instance
                if (config.EnableProviderCaching && _serviceInstances.TryGetValue(name, out var cachedInstance))
                {
                    if (_instanceCreationTimes.TryGetValue(name, out var creationTime) && 
                        !IsInstanceExpired(creationTime, config))
                    {
                        _logger.LogDebug("Retrieved cached named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                        return cachedInstance;
                    }
                    else
                    {
                        // Remove expired instance
                        _serviceInstances.TryRemove(name, out _);
                        _instanceCreationTimes.TryRemove(name, out _);
                    }
                }

                if (_namedServices.TryGetValue(name, out var serviceFactory))
                {
                    var service = serviceFactory();
                    if (service != null && config.EnableProviderCaching)
                    {
                        // Cache the instance
                        _serviceInstances.TryAdd(name, service);
                        _instanceCreationTimes.TryAdd(name, DateTime.UtcNow);
                    }

                    _logger.LogDebug("Retrieved named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);
                    return service;
                }

                _logger.LogWarning("Named service {ServiceName} not found in memory for type {ServiceType}", name, typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Gets a required service instance using the default configuration.
        /// </summary>
        /// <returns>The service instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the service is not available.</exception>
        public T GetRequiredService()
        {
            var service = GetService();
            if (service == null)
            {
                _logger.LogError("Required service not available for type {ServiceType} in memory provider", typeof(T).Name);
                throw new InvalidOperationException($"Required service not available for type {typeof(T).Name} in memory provider");
            }

            return service;
        }

        /// <summary>
        /// Gets a required service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <returns>The service instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the service is not found.</exception>
        public T GetRequiredService(string name)
        {
            var service = GetService(name);
            if (service == null)
            {
                _logger.LogError("Required named service {ServiceName} not found for type {ServiceType} in memory", name, typeof(T).Name);
                throw new InvalidOperationException($"Required named service '{name}' not found for type {typeof(T).Name} in memory provider");
            }

            return service;
        }

        /// <summary>
        /// Gets all available service instances.
        /// </summary>
        /// <returns>An enumerable of all available services.</returns>
        public IEnumerable<T> GetServices()
        {
            try
            {
                _logger.LogDebug("Getting all services for type {ServiceType} from memory provider", typeof(T).Name);

                var services = new List<T>();

                // Get services from DI container
                var diServices = _serviceProvider.GetServices<T>();
                services.AddRange(diServices);

                // Get named services from memory
                foreach (var kvp in _namedServices)
                {
                    try
                    {
                        var service = kvp.Value();
                        if (service != null)
                        {
                            services.Add(service);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error creating service instance {ServiceName} for type {ServiceType} from memory", kvp.Key, typeof(T).Name);
                    }
                }

                _logger.LogDebug("Retrieved {ServiceCount} services for type {ServiceType} from memory provider", services.Count, typeof(T).Name);
                return services;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all services for type {ServiceType} from memory provider", typeof(T).Name);
                return Enumerable.Empty<T>();
            }
        }

        /// <summary>
        /// Asynchronously gets a service instance using the default configuration.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the service instance.</returns>
        public async Task<T?> GetServiceAsync(CancellationToken cancellationToken = default)
        {
            return await Task.Run(GetService, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Asynchronously gets a service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the service instance.</returns>
        public async Task<T?> GetServiceAsync(string name, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() => GetService(name), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Determines whether a service is available using the default configuration.
        /// </summary>
        /// <returns>True if the service is available; otherwise, false.</returns>
        public bool IsServiceAvailable()
        {
            try
            {
                // Check DI container
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                    return true;

                // Check named services in memory
                return _namedServices.Count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking service availability for type {ServiceType} in memory provider", typeof(T).Name);
                return false;
            }
        }

        /// <summary>
        /// Determines whether a service with the specified name is available.
        /// </summary>
        /// <param name="name">The name of the service to check.</param>
        /// <returns>True if the service is available; otherwise, false.</returns>
        public bool IsServiceAvailable(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return IsServiceAvailable();

            try
            {
                return _namedServices.ContainsKey(name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking named service availability {ServiceName} for type {ServiceType} in memory", name, typeof(T).Name);
                return false;
            }
        }

        /// <summary>
        /// Gets metadata about available services.
        /// </summary>
        /// <returns>An enumerable of service metadata.</returns>
        public IEnumerable<ServiceMetadata<T>> GetServiceMetadata()
        {
            try
            {
                return _serviceMetadata.Values.ToList(); // Return a copy to avoid concurrent modification
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for type {ServiceType} from memory", typeof(T).Name);
                return Enumerable.Empty<ServiceMetadata<T>>();
            }
        }

        /// <summary>
        /// Gets metadata for a specific service by name.
        /// </summary>
        /// <param name="name">The name of the service to get metadata for.</param>
        /// <returns>The service metadata, or null if not found.</returns>
        public ServiceMetadata<T>? GetServiceMetadata(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            try
            {
                _serviceMetadata.TryGetValue(name, out var metadata);
                return metadata;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for {ServiceName} of type {ServiceType} from memory", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Registers a named service with this provider in memory.
        /// </summary>
        /// <param name="name">The name of the service.</param>
        /// <param name="serviceFactory">The factory function to create the service.</param>
        /// <param name="metadata">Optional metadata for the service.</param>
        /// <exception cref="ArgumentException">Thrown when name is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown when serviceFactory is null.</exception>
        public void RegisterNamedService(string name, Func<T> serviceFactory, ServiceMetadata<T>? metadata = null)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Service name cannot be null or empty", nameof(name));
            if (serviceFactory == null)
                throw new ArgumentNullException(nameof(serviceFactory));

            try
            {
                _logger.LogDebug("Registering named service {ServiceName} for type {ServiceType} in memory", name, typeof(T).Name);

                _namedServices.AddOrUpdate(name, serviceFactory, (key, oldValue) => serviceFactory);

                // Create or update metadata
                var serviceMetadata = metadata ?? new ServiceMetadata<T>
                {
                    Name = name,
                    ServiceType = typeof(T),
                    IsAvailable = true,
                    Lifetime = S7.Core.Abstractions.Providers.ServiceLifetime.Scoped
                };

                serviceMetadata.Name = name;
                serviceMetadata.ServiceType = typeof(T);
                _serviceMetadata.AddOrUpdate(name, serviceMetadata, (key, oldValue) => serviceMetadata);

                _logger.LogDebug("Successfully registered named service {ServiceName} for type {ServiceType} in memory", name, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering named service {ServiceName} for type {ServiceType} in memory", name, typeof(T).Name);
                throw;
            }
        }

        /// <summary>
        /// Unregisters a named service from this provider and removes it from memory.
        /// </summary>
        /// <param name="name">The name of the service to unregister.</param>
        /// <returns>True if the service was unregistered; otherwise, false.</returns>
        public bool UnregisterNamedService(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            try
            {
                _logger.LogDebug("Unregistering named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);

                var serviceRemoved = _namedServices.TryRemove(name, out _);
                var metadataRemoved = _serviceMetadata.TryRemove(name, out _);
                var instanceRemoved = _serviceInstances.TryRemove(name, out _);
                var timeRemoved = _instanceCreationTimes.TryRemove(name, out _);

                if (serviceRemoved)
                {
                    _logger.LogDebug("Successfully unregistered named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);
                }

                return serviceRemoved;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unregistering named service {ServiceName} for type {ServiceType} from memory", name, typeof(T).Name);
                return false;
            }
        }

        /// <summary>
        /// Clears all cached service instances.
        /// </summary>
        public void ClearCache()
        {
            try
            {
                _logger.LogDebug("Clearing cache for memory provider of type {ServiceType}", typeof(T).Name);

                _serviceInstances.Clear();
                _instanceCreationTimes.Clear();

                lock (_defaultServiceLock)
                {
                    _defaultServiceInstance = null;
                    _defaultServiceCreationTime = default;
                }

                _logger.LogDebug("Successfully cleared cache for memory provider of type {ServiceType}", typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error clearing cache for memory provider of type {ServiceType}", typeof(T).Name);
            }
        }

        /// <summary>
        /// Gets cache statistics for this provider.
        /// </summary>
        /// <returns>A dictionary containing cache statistics.</returns>
        public Dictionary<string, object> GetCacheStatistics()
        {
            try
            {
                return new Dictionary<string, object>
                {
                    ["CachedInstanceCount"] = _serviceInstances.Count,
                    ["NamedServiceCount"] = _namedServices.Count,
                    ["MetadataCount"] = _serviceMetadata.Count,
                    ["HasDefaultService"] = _defaultServiceInstance != null,
                    ["DefaultServiceAge"] = _defaultServiceInstance != null 
                        ? DateTime.UtcNow - _defaultServiceCreationTime 
                        : TimeSpan.Zero
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting cache statistics for memory provider of type {ServiceType}", typeof(T).Name);
                return new Dictionary<string, object>();
            }
        }

        private void InitializeDefaultServices()
        {
            try
            {
                _logger.LogDebug("Initializing memory provider for type {ServiceType}", typeof(T).Name);

                // Initialize with any services available from DI container
                var services = _serviceProvider.GetServices<T>();
                var serviceCount = 0;

                foreach (var service in services)
                {
                    var serviceName = $"Default{serviceCount++}";
                    RegisterNamedService(serviceName, () => service);
                }

                _logger.LogDebug("Initialized memory provider for type {ServiceType} with {ServiceCount} services", 
                    typeof(T).Name, serviceCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error initializing memory provider for type {ServiceType}", typeof(T).Name);
            }
        }

        private bool IsInstanceExpired(DateTime creationTime, ProviderConfiguration config)
        {
            var age = DateTime.UtcNow - creationTime;
            return age.TotalMinutes > config.CacheExpirationMinutes;
        }

        private void CleanupExpiredServices(object? state)
        {
            try
            {
                var config = _configuration.CurrentValue;
                if (!config.EnableProviderCaching)
                    return;

                var expiredKeys = new List<string>();
                var cutoffTime = DateTime.UtcNow.AddMinutes(-config.CacheExpirationMinutes);

                foreach (var kvp in _instanceCreationTimes)
                {
                    if (kvp.Value < cutoffTime)
                    {
                        expiredKeys.Add(kvp.Key);
                    }
                }

                foreach (var key in expiredKeys)
                {
                    _serviceInstances.TryRemove(key, out _);
                    _instanceCreationTimes.TryRemove(key, out _);
                }

                // Check default service expiration
                lock (_defaultServiceLock)
                {
                    if (_defaultServiceInstance != null && _defaultServiceCreationTime < cutoffTime)
                    {
                        _defaultServiceInstance = null;
                        _defaultServiceCreationTime = default;
                    }
                }

                if (expiredKeys.Count > 0)
                {
                    _logger.LogDebug("Cleaned up {ExpiredCount} expired service instances for type {ServiceType}", 
                        expiredKeys.Count, typeof(T).Name);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during cache cleanup for memory provider of type {ServiceType}", typeof(T).Name);
            }
        }

        /// <summary>
        /// Disposes the memory provider and cleans up resources.
        /// </summary>
        public void Dispose()
        {
            try
            {
                _cleanupTimer?.Dispose();
                ClearCache();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing memory provider for type {ServiceType}", typeof(T).Name);
            }
        }
    }
}