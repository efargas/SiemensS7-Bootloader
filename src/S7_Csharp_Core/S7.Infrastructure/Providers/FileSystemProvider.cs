using System;
using System.Collections.Generic;
using System.IO;
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
    /// Provides a file system-based implementation of the service provider pattern.
    /// </summary>
    /// <typeparam name="T">The type of service this provider handles.</typeparam>
    /// <remarks>
    /// This provider stores service configurations and metadata in the file system
    /// and supports persistent service registration and discovery.
    /// </remarks>
    public class FileSystemProvider<T>(
        IServiceProvider serviceProvider,
        IOptionsMonitor<ProviderConfiguration> configuration,
        ILogger<FileSystemProvider<T>> logger) : IDynamicProvider<T> where T : class
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        private readonly IOptionsMonitor<ProviderConfiguration> _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        private readonly ILogger<FileSystemProvider<T>> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly Dictionary<string, Func<T>> _namedServices = new();
        private readonly Dictionary<string, ServiceMetadata<T>> _serviceMetadata = new();
        private readonly object _lock = new();
        private readonly string _basePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "S7Provider",
            typeof(T).Name);

        /// <summary>
        /// Gets a service instance using the default configuration.
        /// </summary>
        /// <returns>The service instance, or null if not available.</returns>
        public T? GetService()
        {
            try
            {
                _logger.LogDebug("Getting default service for type {ServiceType} from file system provider", typeof(T).Name);

                // Try to get from DI container first
                var service = _serviceProvider.GetService<T>();
                if (service != null)
                {
                    _logger.LogDebug("Retrieved service from DI container for type {ServiceType}", typeof(T).Name);
                    return service;
                }

                // Try to get from file system-based named services
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
                        _logger.LogDebug("Using first available file system service for type {ServiceType}", typeof(T).Name);
                        return firstService();
                    }
                }

                _logger.LogWarning("No file system service available for type {ServiceType}", typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting default service for type {ServiceType} from file system provider", typeof(T).Name);
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
                _logger.LogDebug("Getting named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);

                lock (_lock)
                {
                    if (_namedServices.TryGetValue(name, out var serviceFactory))
                    {
                        var service = serviceFactory();
                        _logger.LogDebug("Retrieved named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);
                        return service;
                    }
                }

                // Try to load from file system if not in memory
                if (TryLoadServiceFromFile(name, out var loadedService))
                {
                    _logger.LogDebug("Loaded named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);
                    return loadedService;
                }

                _logger.LogWarning("Named service {ServiceName} not found in file system for type {ServiceType}", name, typeof(T).Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);
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
                _logger.LogError("Required service not available for type {ServiceType} in file system provider", typeof(T).Name);
                throw new InvalidOperationException($"Required service not available for type {typeof(T).Name} in file system provider");
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
                _logger.LogError("Required named service {ServiceName} not found for type {ServiceType} in file system", name, typeof(T).Name);
                throw new InvalidOperationException($"Required named service '{name}' not found for type {typeof(T).Name} in file system provider");
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
                _logger.LogDebug("Getting all services for type {ServiceType} from file system provider", typeof(T).Name);

                var services = new List<T>();

                // Get services from DI container
                var diServices = _serviceProvider.GetServices<T>();
                services.AddRange(diServices);

                // Get named services from memory
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
                            _logger.LogWarning(ex, "Error creating service instance for type {ServiceType} from file system", typeof(T).Name);
                        }
                    }
                }

                // Load additional services from file system
                LoadAllServicesFromFileSystem(services);

                _logger.LogDebug("Retrieved {ServiceCount} services for type {ServiceType} from file system provider", services.Count, typeof(T).Name);
                return services;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all services for type {ServiceType} from file system provider", typeof(T).Name);
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
                lock (_lock)
                {
                    if (_namedServices.Count > 0)
                        return true;
                }

                // Check file system
                return HasServicesInFileSystem();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking service availability for type {ServiceType} in file system provider", typeof(T).Name);
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
                    if (_namedServices.ContainsKey(name))
                        return true;
                }

                // Check file system
                return ServiceExistsInFileSystem(name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking named service availability {ServiceName} for type {ServiceType} in file system", name, typeof(T).Name);
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
                var allMetadata = new List<ServiceMetadata<T>>();

                lock (_lock)
                {
                    allMetadata.AddRange(_serviceMetadata.Values);
                }

                // Load metadata from file system
                LoadMetadataFromFileSystem(allMetadata);

                return allMetadata;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for type {ServiceType} from file system", typeof(T).Name);
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
                    if (_serviceMetadata.TryGetValue(name, out var metadata))
                        return metadata;
                }

                // Try to load from file system
                return LoadMetadataFromFile(name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error getting service metadata for {ServiceName} of type {ServiceType} from file system", name, typeof(T).Name);
                return null;
            }
        }

        /// <summary>
        /// Registers a named service with this provider and persists it to the file system.
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
                _logger.LogDebug("Registering named service {ServiceName} for type {ServiceType} in file system", name, typeof(T).Name);

                lock (_lock)
                {
                    _namedServices[name] = serviceFactory;

                    // Create or update metadata
                    var serviceMetadata = metadata ?? new ServiceMetadata<T>
                    {
                        Name = name,
                        ServiceType = typeof(T),
                        IsAvailable = true,
                        Lifetime = ServiceLifetime.Scoped
                    };

                    serviceMetadata.Name = name;
                    serviceMetadata.ServiceType = typeof(T);
                    _serviceMetadata[name] = serviceMetadata;

                    // Persist to file system
                    PersistServiceToFile(name, serviceMetadata);
                }

                _logger.LogDebug("Successfully registered named service {ServiceName} for type {ServiceType} in file system", name, typeof(T).Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering named service {ServiceName} for type {ServiceType} in file system", name, typeof(T).Name);
                throw;
            }
        }

        /// <summary>
        /// Unregisters a named service from this provider and removes it from the file system.
        /// </summary>
        /// <param name="name">The name of the service to unregister.</param>
        /// <returns>True if the service was unregistered; otherwise, false.</returns>
        public bool UnregisterNamedService(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            try
            {
                _logger.LogDebug("Unregistering named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);

                lock (_lock)
                {
                    var serviceRemoved = _namedServices.Remove(name);
                    var metadataRemoved = _serviceMetadata.Remove(name);

                    // Remove from file system
                    RemoveServiceFromFile(name);

                    if (serviceRemoved)
                    {
                        _logger.LogDebug("Successfully unregistered named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);
                    }

                    return serviceRemoved;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unregistering named service {ServiceName} for type {ServiceType} from file system", name, typeof(T).Name);
                return false;
            }
        }

        private void EnsureDirectoryExists()
        {
            try
            {
                if (!Directory.Exists(_basePath))
                {
                    Directory.CreateDirectory(_basePath);
                    _logger.LogDebug("Created directory {BasePath} for file system provider", _basePath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error creating directory {BasePath} for file system provider", _basePath);
            }
        }

        private void InitializeFromFileSystem()
        {
            try
            {
                _logger.LogDebug("Initializing file system provider for type {ServiceType} from {BasePath}", typeof(T).Name, _basePath);

                if (!Directory.Exists(_basePath))
                    return;

                var metadataFiles = Directory.GetFiles(_basePath, "*.metadata.json");
                foreach (var metadataFile in metadataFiles)
                {
                    try
                    {
                        var serviceName = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(metadataFile));
                        var metadata = LoadMetadataFromFile(serviceName);
                        if (metadata != null)
                        {
                            lock (_lock)
                            {
                                _serviceMetadata[serviceName] = metadata;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error loading metadata from file {MetadataFile}", metadataFile);
                    }
                }

                _logger.LogDebug("Initialized file system provider for type {ServiceType} with {ServiceCount} services",
                    typeof(T).Name, _serviceMetadata.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error initializing file system provider for type {ServiceType}", typeof(T).Name);
            }
        }

        private bool TryLoadServiceFromFile(string name, out T? service)
        {
            service = null;
            try
            {
                // For this implementation, we'll delegate to DI container
                // In a real implementation, you might deserialize service configurations
                service = _serviceProvider.GetService<T>();
                return service != null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error loading service {ServiceName} from file system", name);
                return false;
            }
        }

        private void LoadAllServicesFromFileSystem(List<T> services)
        {
            // Implementation would load services from file system
            // For this example, we'll skip the actual file loading
        }

        private bool HasServicesInFileSystem()
        {
            try
            {
                return Directory.Exists(_basePath) && Directory.GetFiles(_basePath, "*.metadata.json").Length > 0;
            }
            catch
            {
                return false;
            }
        }

        private bool ServiceExistsInFileSystem(string name)
        {
            try
            {
                var metadataPath = Path.Combine(_basePath, $"{name}.metadata.json");
                return File.Exists(metadataPath);
            }
            catch
            {
                return false;
            }
        }

        private void LoadMetadataFromFileSystem(List<ServiceMetadata<T>> allMetadata)
        {
            // Implementation would load all metadata from file system
            // For this example, we'll skip the actual file loading
        }

        private ServiceMetadata<T>? LoadMetadataFromFile(string name)
        {
            try
            {
                var metadataPath = Path.Combine(_basePath, $"{name}.metadata.json");
                if (!File.Exists(metadataPath))
                    return null;

                // In a real implementation, you would deserialize the metadata from JSON
                // For this example, we'll return a basic metadata object
                return new ServiceMetadata<T>
                {
                    Name = name,
                    ServiceType = typeof(T),
                    IsAvailable = true,
                    Lifetime = ServiceLifetime.Scoped,
                    Description = "File system persisted service"
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error loading metadata for service {ServiceName} from file system", name);
                return null;
            }
        }

        private void PersistServiceToFile(string name, ServiceMetadata<T> metadata)
        {
            try
            {
                var metadataPath = Path.Combine(_basePath, $"{name}.metadata.json");
                // In a real implementation, you would serialize the metadata to JSON
                // For this example, we'll create a simple marker file
                File.WriteAllText(metadataPath, $"{{\"name\":\"{name}\",\"type\":\"{typeof(T).Name}\"}}");
                _logger.LogDebug("Persisted service metadata for {ServiceName} to {MetadataPath}", name, metadataPath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error persisting service {ServiceName} to file system", name);
            }
        }

        private void RemoveServiceFromFile(string name)
        {
            try
            {
                var metadataPath = Path.Combine(_basePath, $"{name}.metadata.json");
                if (File.Exists(metadataPath))
                {
                    File.Delete(metadataPath);
                    _logger.LogDebug("Removed service metadata for {ServiceName} from file system", name);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error removing service {ServiceName} from file system", name);
            }
        }
    }
}