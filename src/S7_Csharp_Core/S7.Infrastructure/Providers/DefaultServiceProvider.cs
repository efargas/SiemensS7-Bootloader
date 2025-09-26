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
    /// Provides a default implementation of the service provider pattern with dependency injection support.
    /// </summary>
    /// <typeparam name="T">The type of service this provider handles.</typeparam>
    /// <remarks>
    /// This provider integrates with the Microsoft.Extensions.DependencyInjection container
    /// and supports configuration-driven service selection and lifetime management.
    /// </remarks>
    public class DefaultServiceProvider<T> : IServiceProvider<T> where T : class
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration;
        private readonly ILogger<DefaultServiceProvider<T>> _logger;
        private readonly Dictionary<string, Func<T>> _namedServices = new();
        private readonly Dictionary<string, ServiceMetadata<T>> _serviceMetadata = new();
        private readonly object _lock = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultServiceProvider{T}"/> class.
        /// </summary>
        /// <param name="serviceProvider">The dependency injection service provider.</param>
        /// <param name="configuration">The provider configuration options.</param>
        /// <param name="logger">The logger instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public DefaultServiceProvider(
            IServiceProvider serviceProvider,
            IOptionsMonitor<ProviderConfiguration> configuration,
            ILogger<DefaultServiceProvider<T>> logger)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

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
                _logger.LogDebug("Getting default service for type {ServiceType}", typeof(T).Name);

                // Try to get from DI container first
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                {
                    _logger.LogDebug("Retrieved service from DI container for type {ServiceType}", typeof(T).Name);
                    return service;
                }

                // Try to get from named services
                var config = _configuration.CurrentValue;
                var serviceTypeName = typeof(T).FullName ?? typeof(T).Name;

                if (config.DefaultProviders.TryGetValue(serviceTypeName, out var defaultProviderName))
                {
                    _logger.LogDebug("Using configured default provider {ProviderName} for type {ServiceType}", 
                        defaultProviderName, typeof(T).Name);
                    return GetService(defaultProviderName);
                }

                // Return the first available named service
                lock (_lock)
                {
                    var firstService = _namedServices.Values.FirstOrDefault();
                    if (firstService != null)
                    {
                        _logger.LogDebug("Using first available named service for type {ServiceType}", typeof(T).Name);
                        return firstService();
                    }
                }

                _logger.LogWarning("No service available for type {ServiceType}", typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting default service for type {ServiceType}", typeof(T).Name);
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
                _logger.LogDebug("Getting named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);

                lock (_lock)
                {
                    if (_namedServices.TryGetValue(name, out var serviceFactory))
                    {
                        var service = serviceFactory();
                        _logger.LogDebug("Retrieved named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                        return service;
                    }
                }

                _logger.LogWarning("Named service {ServiceName} not found for type {ServiceType}", name, typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
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
                _logger.LogError("Required service not available for type {ServiceType}", typeof(T).Name);
                throw new InvalidOperationException($"Required service not available for type {typeof(T).Name}");
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
                _logger.LogError("Required named service {ServiceName} not found for type {ServiceType}", name, typeof(T).Name);
                throw new InvalidOperationException($"Required named service '{name}' not found for type {typeof(T).Name}");
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
                _logger.LogDebug("Getting all services for type {ServiceType}", typeof(T).Name);

                var services = new List<T>();

                // Get services from DI container
                var diServices = _serviceProvider.GetServices<T>();
                services.AddRange(diServices);

                // Get named services
                lock (_lock)
                {
                    foreach (var serviceFactory in _namedServices.Values)
                    {
                        try
                        {
                            var service = serviceFactory();
                            if (service != null)
                            {
                                services.Add(service);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Error creating service instance for type {ServiceType}", typeof(T).Name);
                        }
                    }
                }

                _logger.LogDebug("Retrieved {ServiceCount} services for type {ServiceType}", services.Count, typeof(T).Name);
                return services;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all services for type {ServiceType}", typeof(T).Name);
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

                // Check named services
                lock (_lock)
                {
                    return _namedServices.Count > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking service availability for type {ServiceType}", typeof(T).Name);
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
                lock (_lock)
                {
                    return _namedServices.ContainsKey(name);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking named service availability {ServiceName} for type {ServiceType}", name, typeof(T).Name);
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
                lock (_lock)
                {
                    return _serviceMetadata.Values.ToList(); // Return a copy to avoid concurrent modification
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for type {ServiceType}", typeof(T).Name);
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
                lock (_lock)
                {
                    _serviceMetadata.TryGetValue(name, out var metadata);
                    return metadata;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for {ServiceName} of type {ServiceType}", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Registers a named service with this provider.
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
                _logger.LogDebug("Registering named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);

                lock (_lock)
                {
                    _namedServices[name] = serviceFactory;

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
                    _serviceMetadata[name] = serviceMetadata;
                }

                _logger.LogDebug("Successfully registered named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                throw;
            }
        }

        /// <summary>
        /// Unregisters a named service from this provider.
        /// </summary>
        /// <param name="name">The name of the service to unregister.</param>
        /// <returns>True if the service was unregistered; otherwise, false.</returns>
        public bool UnregisterNamedService(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            try
            {
                _logger.LogDebug("Unregistering named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);

                lock (_lock)
                {
                    var serviceRemoved = _namedServices.Remove(name);
                    var metadataRemoved = _serviceMetadata.Remove(name);

                    if (serviceRemoved)
                    {
                        _logger.LogDebug("Successfully unregistered named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                    }

                    return serviceRemoved;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unregistering named service {ServiceName} for type {ServiceType}", name, typeof(T).Name);
                return false;
            }
        }

        private void InitializeDefaultServices()
        {
            try
            {
                _logger.LogDebug("Initializing default services for type {ServiceType}", typeof(T).Name);

                // Initialize with any services available from DI container
                var services = _serviceProvider.GetServices<T>();
                var serviceCount = 0;

                foreach (var service in services)
                {
                    var serviceName = $"Default{serviceCount++}";
                    RegisterNamedService(serviceName, () => service);
                }

                _logger.LogDebug("Initialized {ServiceCount} default services for type {ServiceType}", serviceCount, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error initializing default services for type {ServiceType}", typeof(T).Name);
            }
        }
    }
}