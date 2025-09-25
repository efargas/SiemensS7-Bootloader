using S7.Core.Abstractions.Repositories;

namespace S7.Core.Abstractions.Factories
{
    /// <summary>
    /// Factory interface for creating repository instances with dependency injection support.
    /// </summary>
    public interface IRepositoryFactory
    {
        /// <summary>
        /// Creates a file repository instance.
        /// </summary>
        /// <returns>A configured file repository instance.</returns>
        IFileRepository CreateFileRepository();

        /// <summary>
        /// Creates a memory dump repository instance.
        /// </summary>
        /// <returns>A configured memory dump repository instance.</returns>
        IMemoryDumpRepository CreateMemoryDumpRepository();

        /// <summary>
        /// Creates a unit of work instance for coordinating repository operations.
        /// </summary>
        /// <returns>A configured unit of work instance.</returns>
        IUnitOfWork CreateUnitOfWork();

        /// <summary>
        /// Creates a generic repository instance for the specified entity type.
        /// </summary>
        /// <typeparam name="TEntity">The entity type.</typeparam>
        /// <typeparam name="TKey">The key type.</typeparam>
        /// <returns>A configured generic repository instance.</returns>
        IRepository<TEntity, TKey> CreateRepository<TEntity, TKey>()
            where TEntity : class
            where TKey : notnull;
    }
}