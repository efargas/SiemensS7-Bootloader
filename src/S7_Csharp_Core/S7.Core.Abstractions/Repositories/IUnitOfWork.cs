using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Repositories;

/// <summary>
/// Unit of Work pattern interface for managing transactions across multiple repositories.
/// Ensures data consistency by coordinating changes across multiple data sources.
/// </summary>
public interface IUnitOfWork : IDisposable
{
    /// <summary>
    /// Gets a repository instance for the specified entity type.
    /// </summary>
    /// <typeparam name="TEntity">The entity type</typeparam>
    /// <typeparam name="TKey">The type of the entity's primary key</typeparam>
    /// <returns>A repository instance for the specified entity type</returns>
    IRepository<TEntity, TKey> GetRepository<TEntity, TKey>()
        where TEntity : class
        where TKey : notnull;

    /// <summary>
    /// Commits all pending changes to the underlying data store.
    /// This operation is atomic - either all changes succeed or all fail.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The number of entities affected by the commit operation</returns>
    Task<int> CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back all pending changes, discarding any modifications made within this unit of work.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task RollbackAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Begins a new transaction scope for coordinating changes across repositories.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A transaction scope that can be committed or rolled back</returns>
    Task<ITransactionScope> BeginTransactionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Indicates whether there are any pending changes that need to be committed.
    /// </summary>
    bool HasPendingChanges { get; }

    /// <summary>
    /// Clears all pending changes without committing them to the data store.
    /// This is useful for resetting the unit of work state without affecting the underlying data.
    /// </summary>
    void ClearChanges();
}

/// <summary>
/// Represents a transaction scope that can be committed or rolled back.
/// Provides explicit control over transaction boundaries.
/// </summary>
public interface ITransactionScope : IDisposable
{
    /// <summary>
    /// Commits the transaction, making all changes permanent.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the transaction, discarding all changes made within this scope.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task RollbackAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Indicates whether the transaction has been completed (committed or rolled back).
    /// </summary>
    bool IsCompleted { get; }

    /// <summary>
    /// Gets the unique identifier for this transaction scope.
    /// </summary>
    Guid TransactionId { get; }
}