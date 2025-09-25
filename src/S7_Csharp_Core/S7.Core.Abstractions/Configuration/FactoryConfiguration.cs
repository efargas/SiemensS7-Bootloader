using System.ComponentModel.DataAnnotations;

namespace S7.Core.Abstractions.Configuration
{
    /// <summary>
    /// Configuration options for repository factories.
    /// </summary>
    public class RepositoryFactoryConfiguration
    {
        /// <summary>
        /// The configuration section name.
        /// </summary>
        public const string SectionName = "RepositoryFactory";

        /// <summary>
        /// Gets or sets the default repository implementation type.
        /// </summary>
        [Required]
        public RepositoryImplementationType DefaultImplementationType { get; set; } = RepositoryImplementationType.FileSystem;

        /// <summary>
        /// Gets or sets whether to enable repository caching.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache expiration time in minutes.
        /// </summary>
        [Range(1, 1440)] // 1 minute to 24 hours
        public int CacheExpirationMinutes { get; set; } = 30;

        /// <summary>
        /// Gets or sets the maximum number of cached items per repository.
        /// </summary>
        [Range(10, 10000)]
        public int MaxCacheSize { get; set; } = 1000;

        /// <summary>
        /// Gets or sets whether to validate entities before operations.
        /// </summary>
        public bool EnableValidation { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to enable transaction support.
        /// </summary>
        public bool EnableTransactions { get; set; } = true;

        /// <summary>
        /// Gets or sets the default transaction timeout in seconds.
        /// </summary>
        [Range(1, 3600)] // 1 second to 1 hour
        public int TransactionTimeoutSeconds { get; set; } = 300; // 5 minutes

        /// <summary>
        /// Gets or sets whether to enable performance monitoring.
        /// </summary>
        public bool EnablePerformanceMonitoring { get; set; } = false;
    }

    /// <summary>
    /// Enumeration of available repository implementation types.
    /// </summary>
    public enum RepositoryImplementationType
    {
        /// <summary>
        /// File system-based repository implementation.
        /// </summary>
        FileSystem,

        /// <summary>
        /// In-memory repository implementation for testing.
        /// </summary>
        InMemory,

        /// <summary>
        /// Database-based repository implementation.
        /// </summary>
        Database
    }

    /// <summary>
    /// Configuration options for abstract factories.
    /// </summary>
    public class AbstractFactoryConfiguration
    {
        /// <summary>
        /// The configuration section name.
        /// </summary>
        public const string SectionName = "AbstractFactory";

        /// <summary>
        /// Gets or sets whether to enable factory caching.
        /// </summary>
        public bool EnableFactoryCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the factory cache size.
        /// </summary>
        [Range(10, 1000)]
        public int FactoryCacheSize { get; set; } = 100;

        /// <summary>
        /// Gets or sets whether to enable factory discovery.
        /// </summary>
        public bool EnableFactoryDiscovery { get; set; } = true;

        /// <summary>
        /// Gets or sets the factory discovery timeout in milliseconds.
        /// </summary>
        [Range(100, 10000)]
        public int FactoryDiscoveryTimeoutMs { get; set; } = 5000;

        /// <summary>
        /// Gets or sets whether to validate factory configurations.
        /// </summary>
        public bool ValidateFactoryConfigurations { get; set; } = true;
    }
}