using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Providers;

namespace S7.Infrastructure.Providers
{
    /// <summary>
    /// Provides a caching implementation of the service provider pattern with advanced cache management.
    /// </summary>
    /// <typeparam name="T">The type of service this provider handles.</typeparam>
    /// <remarks>
    /// This provider uses IMemoryCache for sophisticated caching with expiration policies,
    /// cache dependencies, and automatic eviction. It provides excellent performance for
    /// expensive-to-create services while managing memory usage effectively.
    /// </remarks>
    public class CachingProvider<T> : IServiceProvider<T> where T : class
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<CachingProvider<T>> _logger;
        private readonly IMemoryCache _cache;
        private readonly ConcurrentDictionary<string, Func<T>> _namedServices = new();
        private readonly ConcurrentDictionary<string, ServiceMetadata<T>> _serviceMetadata = new();
        private readonly ConcurrentDictionary<string, CacheStatistics> _cacheStats = new();
        private readonly Timer _statsTimer;
        private readonly string _cacheKeyPrefix;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachingProvider{T}"/> class.
        /// </summary>
        /// <param name="serviceProvider">The dependency injection service provider.</param>
        /// <param name="configuration">The provider configuration options.</param>
        /// <param name="logger">The logger instance.</param>
        /// <param name="cache">The memory cache instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public CachingProvider(
            IServiceProvider serviceProvider,
            IOptionsMonitor<ProviderConfiguration> configuration,
            ILogger<CachingProvider<T>> logger,
            IMemoryCache cache)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));

            _cacheKeyPrefix = $"CachingProvider_{typeof(T).Name}_";

            // Initialize statistics timer
            _statsTimer = new Timer(UpdateCacheStatistics, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

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
                _logger.LogDebug("Getting default service for type {ServiceType} from caching provider", typeof(T).Name);

                var config = _configuration.CurrentValue;
                var cacheKey = $"{_cacheKeyPrefix}default";

                // Check cache first if caching is enabled
                if (config.EnableProviderCaching && _cache.TryGetValue(cacheKey, out T? cachedService))
                {
                    RecordCacheHit(cacheKey);
                    _logger.LogDebug("Retrieved cached default service for type {ServiceType}", typeof(T).Name);
                    return cachedService;
                }

                RecordCacheMiss(cacheKey);

                // Try to get from DI container
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                {
                    if (config.EnableProviderCaching)
                    {
                        CacheService(cacheKey, service, config);
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
                    if (instance != null && config.EnableProviderCaching)
                    {
                        CacheService(cacheKey, instance, config);
                    }

                    _logger.LogDebug("Using first available cached service for type {ServiceType}", typeof(T).Name);
                    return instance;
                }

                _logger.LogWarning("No cached service available for type {ServiceType}", typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting default service for type {ServiceType} from caching provider", typeof(T).Name);
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
                _logger.LogDebug("Getting named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);

                var config = _configuration.CurrentValue;
                var cacheKey = $"{_cacheKeyPrefix}{name}";

                // Check cache first if caching is enabled
                if (config.EnableProviderCaching && _cache.TryGetValue(cacheKey, out T? cachedService))
                {
                    RecordCacheHit(cacheKey);
                    _logger.LogDebug("Retrieved cached named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                    return cachedService;
                }

                RecordCacheMiss(cacheKey);

                if (_namedServices.TryGetValue(name, out var serviceFactory))
                {
                    var service = serviceFactory();
                    if (service != null && config.EnableProviderCaching)
                    {
                        CacheService(cacheKey, service, config);
                    }

                    _logger.LogDebug("Retrieved named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);
                    return service;
                }

                _logger.LogWarning("Named service {ServiceName} not found in cache for type {ServiceType}", name, typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);
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
                _logger.LogError("Required service not available for type {ServiceType} in caching provider", typeof(T).Name);
                throw new InvalidOperationException($"Required service not available for type {typeof(T).Name} in caching provider");
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
                _logger.LogError("Required named service {ServiceName} not found for type {ServiceType} in cache", name, typeof(T).Name);
                throw new InvalidOperationException($"Required named service '{name}' not found for type {typeof(T).Name} in caching provider");
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
                _logger.LogDebug("Getting all services for type {ServiceType} from caching provider", typeof(T).Name);

                var services = new List<T>();

                // Get services from DI container
                var diServices = _serviceProvider.GetServices<T>();
                services.AddRange(diServices);

                // Get named services from cache
                foreach (var kvp in _namedServices)
                {
                    try
                    {
                        var service = GetService(kvp.Key); // This will use caching
                        if (service != null)
                        {
                            services.Add(service);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error creating service instance {ServiceName} for type {ServiceType} from cache", kvp.Key, typeof(T).Name);
                    }
                }

                _logger.LogDebug("Retrieved {ServiceCount} services for type {ServiceType} from caching provider", services.Count, typeof(T).Name);
                return services;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all services for type {ServiceType} from caching provider", typeof(T).Name);
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
                // Check cache first
                var config = _configuration.CurrentValue;
                var cacheKey = $"{_cacheKeyPrefix}default";

                if (config.EnableProviderCaching && _cache.TryGetValue(cacheKey, out _))
                    return true;

                // Check DI container
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                    return true;

                // Check named services
                return _namedServices.Count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking service availability for type {ServiceType} in caching provider", typeof(T).Name);
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
                // Check cache first
                var config = _configuration.CurrentValue;
                var cacheKey = $"{_cacheKeyPrefix}{name}";

                if (config.EnableProviderCaching && _cache.TryGetValue(cacheKey, out _))
                    return true;

                return _namedServices.ContainsKey(name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking named service availability {ServiceName} for type {ServiceType} in cache", name, typeof(T).Name);
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
                _logger.LogWarning(ex, "Error getting service metadata for type {ServiceType} from cache", typeof(T).Name);
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
                _logger.LogWarning(ex, "Error getting service metadata for {ServiceName} of type {ServiceType} from cache", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Registers a named service with this provider and sets up caching.
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
                _logger.LogDebug("Registering named service {ServiceName} for type {ServiceType} in cache", name, typeof(T).Name);

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

                // Initialize cache statistics
                var cacheKey = $"{_cacheKeyPrefix}{name}";
                _cacheStats.AddOrUpdate(cacheKey, new CacheStatistics(), (key, oldValue) => oldValue);

                _logger.LogDebug("Successfully registered named service {ServiceName} for type {ServiceType} in cache", name, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering named service {ServiceName} for type {ServiceType} in cache", name, typeof(T).Name);
                throw;
            }
        }

        /// <summary>
        /// Unregisters a named service from this provider and removes it from cache.
        /// </summary>
        /// <param name="name">The name of the service to unregister.</param>
        /// <returns>True if the service was unregistered; otherwise, false.</returns>
        public bool UnregisterNamedService(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            try
            {
                _logger.LogDebug("Unregistering named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);

                var serviceRemoved = _namedServices.TryRemove(name, out _);
                var metadataRemoved = _serviceMetadata.TryRemove(name, out _);

                // Remove from cache
                var cacheKey = $"{_cacheKeyPrefix}{name}";
                _cache.Remove(cacheKey);
                _cacheStats.TryRemove(cacheKey, out _);

                if (serviceRemoved)
                {
                    _logger.LogDebug("Successfully unregistered named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);
                }

                return serviceRemoved;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unregistering named service {ServiceName} for type {ServiceType} from cache", name, typeof(T).Name);
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
                _logger.LogDebug("Clearing cache for caching provider of type {ServiceType}", typeof(T).Name);

                // Remove all entries with our prefix
                foreach (var cacheKey in _cacheStats.Keys)
                {
                    _cache.Remove(cacheKey);
                }

                // Reset statistics
                foreach (var kvp in _cacheStats)
                {
                    kvp.Value.Reset();
                }

                _logger.LogDebug("Successfully cleared cache for caching provider of type {ServiceType}", typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error clearing cache for caching provider of type {ServiceType}", typeof(T).Name);
            }
        }

        /// <summary>
        /// Gets comprehensive cache statistics for this provider.
        /// </summary>
        /// <returns>A dictionary containing cache statistics.</returns>
        public Dictionary<string, object> GetCacheStatistics()
        {
            try
            {
                var totalHits = _cacheStats.Values.Sum(s => s.Hits);
                var totalMisses = _cacheStats.Values.Sum(s => s.Misses);
                var totalRequests = totalHits + totalMisses;
                var hitRatio = totalRequests > 0 ? (double)totalHits / totalRequests : 0.0;

                return new Dictionary<string, object>
                {
                    ["TotalHits"] = totalHits,
                    ["TotalMisses"] = totalMisses,
                    ["TotalRequests"] = totalRequests,
                    ["HitRatio"] = hitRatio,
                    ["CacheKeyCount"] = _cacheStats.Count,
                    ["NamedServiceCount"] = _namedServices.Count,
                    ["MetadataCount"] = _serviceMetadata.Count,
                    ["DetailedStats"] = _cacheStats.ToDictionary(
                        kvp => kvp.Key,
                        kvp => new
                        {
                            Hits = kvp.Value.Hits,
                            Misses = kvp.Value.Misses,
                            LastAccess = kvp.Value.LastAccess,
                            HitRatio = kvp.Value.Hits + kvp.Value.Misses > 0 
                                ? (double)kvp.Value.Hits / (kvp.Value.Hits + kvp.Value.Misses) 
                                : 0.0
                        })
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting cache statistics for caching provider of type {ServiceType}", typeof(T).Name);
                return new Dictionary<string, object>();
            }
        }

        private void InitializeDefaultServices()
        {
            try
            {
                _logger.LogDebug("Initializing caching provider for type {ServiceType}", typeof(T).Name);

                // Initialize with any services available from DI container
                var services = _serviceProvider.GetServices<T>();
                var serviceCount = 0;

                foreach (var service in services)
                {
                    var serviceName = $"Default{serviceCount++}";
                    RegisterNamedService(serviceName, () => service);
                }

                _logger.LogDebug("Initialized caching provider for type {ServiceType} with {ServiceCount} services", 
                    typeof(T).Name, serviceCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error initializing caching provider for type {ServiceType}", typeof(T).Name);
            }
        }

        private void CacheService(string cacheKey, T service, ProviderConfiguration config)
        {
            try
            {
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(config.CacheExpirationMinutes),
                    SlidingExpiration = TimeSpan.FromMinutes(config.CacheExpirationMinutes / 2),
                    Priority = CacheItemPriority.Normal
                };

                // Add eviction callback for statistics
                cacheOptions.RegisterPostEvictionCallback((key, value, reason, state) =>
                {
                    _logger.LogDebug("Cache entry {CacheKey} evicted due to {Reason}", key, reason);
                });

                _cache.Set(cacheKey, service, cacheOptions);
                _logger.LogDebug("Cached service with key {CacheKey}", cacheKey);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error caching service with key {CacheKey}", cacheKey);
            }
        }

        private void RecordCacheHit(string cacheKey)
        {
            if (_cacheStats.TryGetValue(cacheKey, out var stats))
            {
                stats.RecordHit();
            }
        }

        private void RecordCacheMiss(string cacheKey)
        {
            if (_cacheStats.TryGetValue(cacheKey, out var stats))
            {
                stats.RecordMiss();
            }
        }

        private void UpdateCacheStatistics(object? state)
        {
            try
            {
                var config = _configuration.CurrentValue;
                if (config.EnableMetrics)
                {
                    var stats = GetCacheStatistics();
                    _logger.LogDebug("Cache statistics for {ServiceType}: {Stats}", typeof(T).Name, stats);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error updating cache statistics for type {ServiceType}", typeof(T).Name);
            }
        }

        /// <summary>
        /// Disposes the caching provider and cleans up resources.
        /// </summary>
        public void Dispose()
        {
            try
            {
                _statsTimer?.Dispose();
                ClearCache();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing caching provider for type {ServiceType}", typeof(T).Name);
            }
        }

        private class CacheStatistics
        {
            private long _hits;
            private long _misses;
            private DateTime _lastAccess;

            public long Hits => _hits;
            public long Misses => _misses;
            public DateTime LastAccess => _lastAccess;

            public void RecordHit()
            {
                Interlocked.Increment(ref _hits);
                _lastAccess = DateTime.UtcNow;
            }

            public void RecordMiss()
            {
                Interlocked.Increment(ref _misses);
                _lastAccess = DateTime.UtcNow;
            }

            public void Reset()
            {
                Interlocked.Exchange(ref _hits, 0);
                Interlocked.Exchange(ref _misses, 0);
                _lastAccess = DateTime.UtcNow;
            }
        }
    }
}