using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Repositories;

/// <summary>
/// Generic repository interface for data access operations.
/// Provides a consistent abstraction layer for CRUD operations across different data sources.
/// </summary>
/// <typeparam name="TEntity">The entity type managed by this repository</typeparam>
/// <typeparam name="TKey">The type of the entity's primary key</typeparam>
public interface IRepository<TEntity, TKey> : IDisposable
    where TEntity : class
    where TKey : notnull
{
    /// <summary>
    /// Retrieves an entity by its unique identifier.
    /// </summary>
    /// <param name="id">The unique identifier of the entity</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The entity if found, null otherwise</returns>
    Task<TEntity?> GetByIdAsync(TKey id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all entities that match the specified predicate.
    /// </summary>
    /// <param name="predicate">The condition to filter entities</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A collection of entities matching the predicate</returns>
    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all entities from the repository.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>All entities in the repository</returns>
    Task<IEnumerable<TEntity>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new entity to the repository.
    /// </summary>
    /// <param name="entity">The entity to add</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The added entity with any generated values</returns>
    Task<TEntity> AddAsync(TEntity entity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds multiple entities to the repository in a single operation.
    /// </summary>
    /// <param name="entities">The entities to add</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The added entities with any generated values</returns>
    Task<IEnumerable<TEntity>> AddRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing entity in the repository.
    /// </summary>
    /// <param name="entity">The entity to update</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The updated entity</returns>
    Task<TEntity> UpdateAsync(TEntity entity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an entity from the repository by its identifier.
    /// </summary>
    /// <param name="id">The unique identifier of the entity to remove</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>True if the entity was removed, false if not found</returns>
    Task<bool> DeleteAsync(TKey id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an entity from the repository.
    /// </summary>
    /// <param name="entity">The entity to remove</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>True if the entity was removed, false if not found</returns>
    Task<bool> DeleteAsync(TEntity entity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if an entity with the specified identifier exists.
    /// </summary>
    /// <param name="id">The unique identifier to check</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>True if the entity exists, false otherwise</returns>
    Task<bool> ExistsAsync(TKey id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the total count of entities in the repository.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The total number of entities</returns>
    Task<long> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the count of entities that match the specified predicate.
    /// </summary>
    /// <param name="predicate">The condition to filter entities</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The number of entities matching the predicate</returns>
    Task<long> CountAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default);
}