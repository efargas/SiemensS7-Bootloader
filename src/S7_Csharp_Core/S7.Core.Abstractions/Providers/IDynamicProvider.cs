using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace S7.Core.Abstractions.Providers
{
    /// <summary>
    /// Defines a dynamic provider that integrates with dependency injection containers
    /// and provides service discovery and lifetime management capabilities.
    /// </summary>
    /// <remarks>
    /// This interface extends the standard .NET service provider pattern with additional
    /// capabilities for service discovery, metadata, and async operations.
    /// </remarks>
    public interface IDynamicProvider<T> where T : class
    {
        /// <summary>
        /// Gets a service instance using the default configuration.
        /// </summary>
        /// <returns>The service instance, or null if not available.</returns>
        T? GetService();

        /// <summary>
        /// Gets a service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <returns>The service instance, or null if not found.</returns>
        T? GetService(string name);

        /// <summary>
        /// Gets a required service instance using the default configuration.
        /// </summary>
        /// <returns>The service instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the service is not available.</exception>
        T GetRequiredService();

        /// <summary>
        /// Gets a required service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <returns>The service instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the service is not found.</exception>
        T GetRequiredService(string name);

        /// <summary>
        /// Gets all available service instances.
        /// </summary>
        /// <returns>An enumerable of all available services.</returns>
        IEnumerable<T> GetServices();

        /// <summary>
        /// Asynchronously gets a service instance using the default configuration.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the service instance.</returns>
        Task<T?> GetServiceAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously gets a service instance by name.
        /// </summary>
        /// <param name="name">The name of the service to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the service instance.</returns>
        Task<T?> GetServiceAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>
        /// Determines whether a service is available using the default configuration.
        /// </summary>
        /// <returns>True if the service is available; otherwise, false.</returns>
        bool IsServiceAvailable();

        /// <summary>
        /// Determines whether a service with the specified name is available.
        /// </summary>
        /// <param name="name">The name of the service to check.</param>
        /// <returns>True if the service is available; otherwise, false.</returns>
        bool IsServiceAvailable(string name);

        /// <summary>
        /// Gets metadata about available services.
        /// </summary>
        /// <returns>An enumerable of service metadata.</returns>
        IEnumerable<ServiceMetadata<T>> GetServiceMetadata();

        /// <summary>
        /// Gets metadata for a specific service by name.
        /// </summary>
        /// <param name="name">The name of the service to get metadata for.</param>
        /// <returns>The service metadata, or null if not found.</returns>
        ServiceMetadata<T>? GetServiceMetadata(string name);
    }

    /// <summary>
    /// Represents metadata about a service registration.
    /// </summary>
    /// <typeparam name="T">The type of service.</typeparam>
    public class ServiceMetadata<T> where T : class
    {
        /// <summary>
        /// Gets or sets the service name.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the service type.
        /// </summary>
        public Type ServiceType { get; set; } = typeof(T);

        /// <summary>
        /// Gets or sets the implementation type.
        /// </summary>
        public Type? ImplementationType { get; set; }

        /// <summary>
        /// Gets or sets the service lifetime.
        /// </summary>
        public ServiceLifetime Lifetime { get; set; }

        /// <summary>
        /// Gets or sets additional metadata properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();

        /// <summary>
        /// Gets or sets a value indicating whether the service is available.
        /// </summary>
        public bool IsAvailable { get; set; } = true;

        /// <summary>
        /// Gets or sets the service description.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets the service version.
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the service priority for selection.
        /// </summary>
        public int Priority { get; set; } = 0;
    }
}