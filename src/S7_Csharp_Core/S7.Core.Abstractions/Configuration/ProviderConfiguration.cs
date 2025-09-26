using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using S7.Core.Abstractions.Providers;

namespace S7.Core.Abstractions.Configuration
{
    /// <summary>
    /// Represents configuration settings for service providers.
    /// </summary>
    /// <remarks>
    /// This configuration supports provider selection, discovery settings,
    /// and provider-specific options.
    /// </remarks>
    public class ProviderConfiguration
    {
        /// <summary>
        /// The configuration section name for provider settings.
        /// </summary>
        public const string SectionName = "Providers";

        /// <summary>
        /// Gets or sets the default provider selection strategy.
        /// </summary>
        [Required]
        public ProviderSelectionStrategy DefaultSelectionStrategy { get; set; } = ProviderSelectionStrategy.FirstAvailable;

        /// <summary>
        /// Gets or sets a value indicating whether automatic provider discovery is enabled.
        /// </summary>
        public bool EnableAutoDiscovery { get; set; } = true;

        /// <summary>
        /// Gets or sets the assemblies to scan for provider discovery.
        /// </summary>
        public List<string> DiscoveryAssemblies { get; set; } = new();

        /// <summary>
        /// Gets or sets the provider-specific configurations.
        /// </summary>
        public Dictionary<string, ProviderOptions> Providers { get; set; } = new();

        /// <summary>
        /// Gets or sets the default provider names for specific service types.
        /// </summary>
        public Dictionary<string, string> DefaultProviders { get; set; } = new();

        /// <summary>
        /// Gets or sets a value indicating whether provider validation is enabled at startup.
        /// </summary>
        public bool EnableStartupValidation { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for provider operations in seconds.
        /// </summary>
        [Range(1, 300)]
        public int OperationTimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// Gets or sets a value indicating whether provider caching is enabled.
        /// </summary>
        public bool EnableProviderCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache expiration time in minutes.
        /// </summary>
        [Range(1, 1440)]
        public int CacheExpirationMinutes { get; set; } = 60;

        /// <summary>
        /// Gets or sets the maximum number of cached providers.
        /// </summary>
        [Range(1, 1000)]
        public int MaxCachedProviders { get; set; } = 100;

        /// <summary>
        /// Gets or sets a value indicating whether provider metrics collection is enabled.
        /// </summary>
        public bool EnableMetrics { get; set; } = false;

        /// <summary>
        /// Gets or sets additional configuration properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    /// <summary>
    /// Represents configuration options for a specific provider.
    /// </summary>
    public class ProviderOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether the provider is enabled.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the provider priority for selection.
        /// </summary>
        public int Priority { get; set; } = 0;

        /// <summary>
        /// Gets or sets the provider lifetime.
        /// </summary>
        public ServiceLifetime Lifetime { get; set; } = ServiceLifetime.Scoped;

        /// <summary>
        /// Gets or sets the provider-specific configuration properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();

        /// <summary>
        /// Gets or sets the provider description.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets the provider version.
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the provider tags for categorization.
        /// </summary>
        public List<string> Tags { get; set; } = new();

        /// <summary>
        /// Gets or sets the provider dependencies.
        /// </summary>
        public List<string> Dependencies { get; set; } = new();

        /// <summary>
        /// Gets or sets the health check configuration for the provider.
        /// </summary>
        public ProviderHealthCheckOptions? HealthCheck { get; set; }
    }

    /// <summary>
    /// Represents health check configuration for a provider.
    /// </summary>
    public class ProviderHealthCheckOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether health checks are enabled.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the health check interval in seconds.
        /// </summary>
        [Range(1, 3600)]
        public int IntervalSeconds { get; set; } = 60;

        /// <summary>
        /// Gets or sets the health check timeout in seconds.
        /// </summary>
        [Range(1, 60)]
        public int TimeoutSeconds { get; set; } = 10;

        /// <summary>
        /// Gets or sets the number of consecutive failures before marking as unhealthy.
        /// </summary>
        [Range(1, 10)]
        public int FailureThreshold { get; set; } = 3;

        /// <summary>
        /// Gets or sets the health check endpoint or method name.
        /// </summary>
        public string? Endpoint { get; set; }

        /// <summary>
        /// Gets or sets additional health check properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    /// <summary>
    /// Defines the strategy for selecting providers when multiple are available.
    /// </summary>
    public enum ProviderSelectionStrategy
    {
        /// <summary>
        /// Select the first available provider.
        /// </summary>
        FirstAvailable,

        /// <summary>
        /// Select the provider with the highest priority.
        /// </summary>
        HighestPriority,

        /// <summary>
        /// Select the provider with the lowest priority.
        /// </summary>
        LowestPriority,

        /// <summary>
        /// Select a random available provider.
        /// </summary>
        Random,

        /// <summary>
        /// Use round-robin selection among available providers.
        /// </summary>
        RoundRobin,

        /// <summary>
        /// Select based on load balancing metrics.
        /// </summary>
        LoadBalanced,

        /// <summary>
        /// Select based on custom selection logic.
        /// </summary>
        Custom
    }

    /// <summary>
    /// Defines the type of provider implementation.
    /// </summary>
    public enum ProviderImplementationType
    {
        /// <summary>
        /// Default provider implementation.
        /// </summary>
        Default,

        /// <summary>
        /// In-memory provider implementation.
        /// </summary>
        InMemory,

        /// <summary>
        /// File-based provider implementation.
        /// </summary>
        FileBased,

        /// <summary>
        /// Database-backed provider implementation.
        /// </summary>
        Database,

        /// <summary>
        /// Network-based provider implementation.
        /// </summary>
        Network,

        /// <summary>
        /// Cached provider implementation.
        /// </summary>
        Cached,

        /// <summary>
        /// Custom provider implementation.
        /// </summary>
        Custom
    }
}