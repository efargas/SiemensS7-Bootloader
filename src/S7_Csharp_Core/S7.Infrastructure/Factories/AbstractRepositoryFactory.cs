using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Factories;
using S7.Core.Abstractions.Repositories;

namespace S7.Infrastructure.Factories
{
    /// <summary>
    /// Abstract factory for creating repository families with dependency injection support.
    /// Provides a unified interface for creating related repository objects.
    /// </summary>
    public class AbstractRepositoryFactory : IAbstractFactory<IRepositoryFactory>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly AbstractFactoryConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="AbstractRepositoryFactory"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider for dependency resolution.</param>
        /// <param name="options">The configuration options for the abstract factory.</param>
        /// <exception cref="ArgumentNullException">Thrown when serviceProvider or options is null.</exception>
        public AbstractRepositoryFactory(
            IServiceProvider serviceProvider,
            IOptions<AbstractFactoryConfiguration> options)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _configuration = options?.Value ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Creates a repository factory instance.
        /// </summary>
        /// <returns>A configured repository factory instance.</returns>
        public IRepositoryFactory Create()
        {
            if (_configuration.EnableFactoryCaching)
            {
                // Try to get cached factory from service provider
                var cachedFactory = _serviceProvider.GetService<IRepositoryFactory>();
                if (cachedFactory != null)
                {
                    return cachedFactory;
                }
            }

            // Create new factory instance
            var repositoryOptions = _serviceProvider.GetService<IOptions<RepositoryFactoryConfiguration>>();
            if (repositoryOptions == null)
            {
                throw new InvalidOperationException("RepositoryFactoryConfiguration not registered in DI container.");
            }

            return new RepositoryFactory(_serviceProvider, repositoryOptions);
        }
    }

    /// <summary>
    /// Abstract factory for creating file repositories with configuration parameters.
    /// </summary>
    public class FileRepositoryAbstractFactory : IAbstractFactory<IFileRepository, RepositoryImplementationType>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRepositoryFactory _repositoryFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileRepositoryAbstractFactory"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider for dependency resolution.</param>
        /// <param name="repositoryFactory">The repository factory for creating instances.</param>
        /// <exception cref="ArgumentNullException">Thrown when serviceProvider or repositoryFactory is null.</exception>
        public FileRepositoryAbstractFactory(
            IServiceProvider serviceProvider,
            IRepositoryFactory repositoryFactory)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _repositoryFactory = repositoryFactory ?? throw new ArgumentNullException(nameof(repositoryFactory));
        }

        /// <summary>
        /// Creates a file repository instance with the specified implementation type.
        /// </summary>
        /// <param name="implementationType">The implementation type to create.</param>
        /// <returns>A configured file repository instance.</returns>
        public IFileRepository Create(RepositoryImplementationType implementationType)
        {
            // For now, we'll use the repository factory's default implementation
            // In the future, this could be enhanced to support different implementation types
            return _repositoryFactory.CreateFileRepository();
        }
    }

    /// <summary>
    /// Abstract factory for creating memory dump repositories with configuration parameters.
    /// </summary>
    public class MemoryDumpRepositoryAbstractFactory : IAbstractFactory<IMemoryDumpRepository, RepositoryImplementationType>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRepositoryFactory _repositoryFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryDumpRepositoryAbstractFactory"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider for dependency resolution.</param>
        /// <param name="repositoryFactory">The repository factory for creating instances.</param>
        /// <exception cref="ArgumentNullException">Thrown when serviceProvider or repositoryFactory is null.</exception>
        public MemoryDumpRepositoryAbstractFactory(
            IServiceProvider serviceProvider,
            IRepositoryFactory repositoryFactory)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _repositoryFactory = repositoryFactory ?? throw new ArgumentNullException(nameof(repositoryFactory));
        }

        /// <summary>
        /// Creates a memory dump repository instance with the specified implementation type.
        /// </summary>
        /// <param name="implementationType">The implementation type to create.</param>
        /// <returns>A configured memory dump repository instance.</returns>
        public IMemoryDumpRepository Create(RepositoryImplementationType implementationType)
        {
            // For now, we'll use the repository factory's default implementation
            // In the future, this could be enhanced to support different implementation types
            return _repositoryFactory.CreateMemoryDumpRepository();
        }
    }

    /// <summary>
    /// Abstract factory for creating unit of work instances with transaction configuration.
    /// </summary>
    public class UnitOfWorkAbstractFactory : IAbstractFactory<IUnitOfWork, bool, int>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IRepositoryFactory _repositoryFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="UnitOfWorkAbstractFactory"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider for dependency resolution.</param>
        /// <param name="repositoryFactory">The repository factory for creating instances.</param>
        /// <exception cref="ArgumentNullException">Thrown when serviceProvider or repositoryFactory is null.</exception>
        public UnitOfWorkAbstractFactory(
            IServiceProvider serviceProvider,
            IRepositoryFactory repositoryFactory)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _repositoryFactory = repositoryFactory ?? throw new ArgumentNullException(nameof(repositoryFactory));
        }

        /// <summary>
        /// Creates a unit of work instance with the specified transaction configuration.
        /// </summary>
        /// <param name="enableTransactions">Whether to enable transaction support.</param>
        /// <param name="timeoutSeconds">The transaction timeout in seconds.</param>
        /// <returns>A configured unit of work instance.</returns>
        public IUnitOfWork Create(bool enableTransactions, int timeoutSeconds)
        {
            // For now, we'll use the repository factory's default implementation
            // In the future, this could be enhanced to support transaction configuration
            return _repositoryFactory.CreateUnitOfWork();
        }
    }
}