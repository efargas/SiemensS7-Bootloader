using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Repositories;

namespace S7.Infrastructure.Repositories;

/// <summary>
/// File-based Unit of Work implementation that coordinates transactions across multiple file repositories.
/// Provides atomic operations and rollback capabilities for file-based data operations.
/// </summary>
public class FileUnitOfWork() : IUnitOfWork
{
    private readonly ConcurrentDictionary<Type, object> _repositories = new();
    private readonly List<ITransactionOperation> _pendingOperations = new();
    private readonly SemaphoreSlim _operationSemaphore = new(1, 1);
    private bool _disposed;

    /// <inheritdoc />
    public bool HasPendingChanges => _pendingOperations.Count > 0;

    /// <inheritdoc />
    public IRepository<TEntity, TKey> GetRepository<TEntity, TKey>()
        where TEntity : class
        where TKey : notnull
    {
        var repositoryType = typeof(IRepository<TEntity, TKey>);
        
        return (IRepository<TEntity, TKey>)_repositories.GetOrAdd(repositoryType, _ =>
        {
            // For this implementation, we'll create specific repository types based on the entity
            if (typeof(TEntity) == typeof(FileEntity) && typeof(TKey) == typeof(string))
            {
                return new FileRepository();
            }
            
            // For other entity types, you would add more specific repository implementations
            throw new NotSupportedException($"Repository for entity type {typeof(TEntity).Name} with key type {typeof(TKey).Name} is not supported.");
        });
    }

    /// <inheritdoc />
    public async Task<int> CommitAsync(CancellationToken cancellationToken = default)
    {
        await _operationSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_pendingOperations.Count == 0)
            {
                return 0;
            }

            var affectedCount = 0;
            var executedOperations = new List<ITransactionOperation>();

            try
            {
                // Execute all pending operations
                foreach (var operation in _pendingOperations)
                {
                    await operation.ExecuteAsync(cancellationToken).ConfigureAwait(false);
                    executedOperations.Add(operation);
                    affectedCount++;
                }

                // Clear pending operations after successful execution
                _pendingOperations.Clear();
                return affectedCount;
            }
            catch (Exception)
            {
                // Rollback executed operations in reverse order
                for (int i = executedOperations.Count - 1; i >= 0; i--)
                {
                    try
                    {
                        await executedOperations[i].RollbackAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception rollbackEx)
                    {
                        // Log rollback failures but don't throw to avoid masking the original exception
                        // In a real implementation, you'd use a proper logging framework
                        Console.WriteLine($"Rollback failed for operation {i}: {rollbackEx.Message}");
                    }
                }

                throw;
            }
        }
        finally
        {
            _operationSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        await _operationSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // For file-based operations, rollback typically means discarding pending changes
            _pendingOperations.Clear();
        }
        finally
        {
            _operationSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ITransactionScope> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        return new FileTransactionScope(this);
    }

    /// <inheritdoc />
    public void ClearChanges()
    {
        _pendingOperations.Clear();
    }

    /// <summary>
    /// Adds a transaction operation to the pending operations list.
    /// </summary>
    /// <param name="operation">The operation to add</param>
    internal void AddOperation(ITransactionOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        _pendingOperations.Add(operation);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Dispose all repositories
        foreach (var repository in _repositories.Values)
        {
            if (repository is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        _repositories.Clear();
        _pendingOperations.Clear();
        _operationSemaphore.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// File-based transaction scope implementation.
/// </summary>
internal class FileTransactionScope(FileUnitOfWork unitOfWork) : ITransactionScope
{
    private readonly FileUnitOfWork _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
    private bool _disposed;

    /// <inheritdoc />
    public Guid TransactionId { get; } = Guid.NewGuid();

    /// <inheritdoc />
    public bool IsCompleted { get; private set; }

    /// <inheritdoc />
    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        if (IsCompleted)
        {
            throw new InvalidOperationException("Transaction has already been completed.");
        }

        try
        {
            await _unitOfWork.CommitAsync(cancellationToken).ConfigureAwait(false);
            IsCompleted = true;
        }
        catch (Exception)
        {
            IsCompleted = true;
            throw;
        }
    }

    /// <inheritdoc />
    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        if (IsCompleted)
        {
            throw new InvalidOperationException("Transaction has already been completed.");
        }

        try
        {
            await _unitOfWork.RollbackAsync(cancellationToken).ConfigureAwait(false);
            IsCompleted = true;
        }
        catch (Exception)
        {
            IsCompleted = true;
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (!IsCompleted)
        {
            // Auto-rollback if not explicitly committed
            try
            {
                RollbackAsync().GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // Suppress exceptions during disposal
            }
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Represents a transaction operation that can be executed and rolled back.
/// </summary>
internal interface ITransactionOperation
{
    /// <summary>
    /// Executes the operation.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task ExecuteAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Rolls back the operation.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task RollbackAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// File copy operation that can be rolled back.
/// </summary>
internal class FileCopyOperation(string sourcePath, string destinationPath, bool overwrite = false) : ITransactionOperation
{
    private readonly string _sourcePath = sourcePath ?? throw new ArgumentNullException(nameof(sourcePath));
    private readonly string _destinationPath = destinationPath ?? throw new ArgumentNullException(nameof(destinationPath));
    private readonly bool _overwrite = overwrite;
    private bool _executed;
    private bool _destinationExisted;
    private string? _backupPath;

    public async Task ExecuteAsync(CancellationToken cancellationToken = default)
    {
        if (_executed)
        {
            return;
        }

        _destinationExisted = File.Exists(_destinationPath);
        
        if (_destinationExisted && _overwrite)
        {
            // Create backup for rollback
            _backupPath = _destinationPath + ".backup." + Guid.NewGuid().ToString("N")[..8];
            File.Copy(_destinationPath, _backupPath);
        }

        File.Copy(_sourcePath, _destinationPath, _overwrite);
        _executed = true;
    }

    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        if (!_executed)
        {
            return;
        }

        try
        {
            if (_destinationExisted && !string.IsNullOrEmpty(_backupPath))
            {
                // Restore from backup
                File.Copy(_backupPath, _destinationPath, true);
                File.Delete(_backupPath);
            }
            else if (!_destinationExisted && File.Exists(_destinationPath))
            {
                // Delete the file we created
                File.Delete(_destinationPath);
            }
        }
        finally
        {
            _executed = false;
        }
    }
}