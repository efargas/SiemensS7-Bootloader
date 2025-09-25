using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Repositories;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Infrastructure.Repositories;

/// <summary>
/// File-based repository implementation that provides data access operations for file entities.
/// Integrates with the existing virtual file reader infrastructure for optimal performance.
/// </summary>
public class FileRepository : IFileRepository
{
    private readonly ConcurrentDictionary<string, IVirtualFileReader> _readerCache;
    private readonly ConcurrentDictionary<string, FileEntity> _entityCache;
    private readonly SemaphoreSlim _cacheSemaphore;
    private readonly int _maxCacheSize;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the FileRepository class.
    /// </summary>
    /// <param name="maxCacheSize">Maximum number of file readers to cache</param>
    public FileRepository(int maxCacheSize = 50)
    {
        _maxCacheSize = maxCacheSize;
        _readerCache = new ConcurrentDictionary<string, IVirtualFileReader>();
        _entityCache = new ConcurrentDictionary<string, FileEntity>();
        _cacheSemaphore = new SemaphoreSlim(1, 1);
    }

    /// <inheritdoc />
    public async Task<FileEntity?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        
        if (_entityCache.TryGetValue(id, out var cachedEntity))
        {
            return cachedEntity;
        }

        if (!File.Exists(id))
        {
            return null;
        }

        var fileInfo = new FileInfo(id);
        var entity = new FileEntity(
            FilePath: id,
            Size: fileInfo.Length,
            CreatedAt: fileInfo.CreationTime,
            ModifiedAt: fileInfo.LastWriteTime,
            Checksum: await ComputeFileChecksumAsync(id, cancellationToken).ConfigureAwait(false)
        );

        _entityCache.TryAdd(id, entity);
        return entity;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<FileEntity>> FindAsync(Expression<Func<FileEntity, bool>> predicate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        // For file-based operations, we need to scan directories
        // This is a simplified implementation - in a real scenario, you might want to index files
        var allFiles = new List<FileEntity>();
        
        // Get all cached entities first
        var cachedEntities = _entityCache.Values.ToList();
        allFiles.AddRange(cachedEntities);

        // Apply the predicate
        var compiledPredicate = predicate.Compile();
        return allFiles.Where(compiledPredicate);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<FileEntity>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return _entityCache.Values.ToList();
    }

    /// <inheritdoc />
    public async Task<FileEntity> AddAsync(FileEntity entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);

        // For file entities, "adding" means ensuring the file exists and is tracked
        if (!File.Exists(entity.FilePath))
        {
            throw new FileNotFoundException($"File not found: {entity.FilePath}");
        }

        _entityCache.TryAdd(entity.FilePath, entity);
        return entity;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<FileEntity>> AddRangeAsync(IEnumerable<FileEntity> entities, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entities);

        var addedEntities = new List<FileEntity>();
        foreach (var entity in entities)
        {
            var added = await AddAsync(entity, cancellationToken).ConfigureAwait(false);
            addedEntities.Add(added);
        }

        return addedEntities;
    }

    /// <inheritdoc />
    public async Task<FileEntity> UpdateAsync(FileEntity entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);

        if (!File.Exists(entity.FilePath))
        {
            throw new FileNotFoundException($"File not found: {entity.FilePath}");
        }

        // Update the cached entity
        _entityCache.AddOrUpdate(entity.FilePath, entity, (key, oldValue) => entity);
        
        // Invalidate the reader cache for this file since it may have changed
        if (_readerCache.TryRemove(entity.FilePath, out var oldReader))
        {
            oldReader.Dispose();
        }

        return entity;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        if (!File.Exists(id))
        {
            return false;
        }

        try
        {
            File.Delete(id);
            _entityCache.TryRemove(id, out _);
            
            if (_readerCache.TryRemove(id, out var reader))
            {
                reader.Dispose();
            }

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(FileEntity entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);
        return await DeleteAsync(entity.FilePath, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return File.Exists(id);
    }

    /// <inheritdoc />
    public async Task<long> CountAsync(CancellationToken cancellationToken = default)
    {
        return _entityCache.Count;
    }

    /// <inheritdoc />
    public async Task<long> CountAsync(Expression<Func<FileEntity, bool>> predicate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        
        var entities = await FindAsync(predicate, cancellationToken).ConfigureAwait(false);
        return entities.LongCount();
    }

    /// <inheritdoc />
    public async Task<Page> ReadPageAsync(string filePath, long pageIndex, int pageSize, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        
        var reader = await GetOrCreateReaderAsync(filePath, cancellationToken).ConfigureAwait(false);
        return await reader.ReadPageAsync(pageIndex, pageSize, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<Page>> ReadPagesAsync(string filePath, IEnumerable<long> pageIndices, int pageSize, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(pageIndices);

        var reader = await GetOrCreateReaderAsync(filePath, cancellationToken).ConfigureAwait(false);
        var pages = new List<Page>();

        foreach (var pageIndex in pageIndices)
        {
            var page = await reader.ReadPageAsync(pageIndex, pageSize, cancellationToken).ConfigureAwait(false);
            pages.Add(page);
        }

        return pages;
    }

    /// <inheritdoc />
    public async Task WritePageAsync(string filePath, Page page, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(page);

        // For write operations, we need to work directly with the file
        // This is a simplified implementation - in production, you'd want more sophisticated write handling
        using var fileStream = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
        
        var offset = page.PageIndex * page.Data.Length;
        fileStream.Seek(offset, SeekOrigin.Begin);
        
        await fileStream.WriteAsync(page.Data, cancellationToken).ConfigureAwait(false);
        await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cached reader since file has changed
        if (_readerCache.TryRemove(filePath, out var reader))
        {
            reader.Dispose();
        }

        // Update entity cache
        if (_entityCache.TryGetValue(filePath, out var entity))
        {
            var fileInfo = new FileInfo(filePath);
            var updatedEntity = entity with 
            { 
                Size = fileInfo.Length, 
                ModifiedAt = fileInfo.LastWriteTime,
                Checksum = null // Will be recomputed on next access
            };
            _entityCache.TryUpdate(filePath, updatedEntity, entity);
        }
    }

    /// <inheritdoc />
    public async Task WritePagesAsync(string filePath, IEnumerable<Page> pages, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(pages);

        foreach (var page in pages)
        {
            await WritePageAsync(filePath, page, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async Task<long> GetFileLengthAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}");
        }

        var fileInfo = new FileInfo(filePath);
        return fileInfo.Length;
    }

    /// <inheritdoc />
    public async Task<FileMetadata> GetFileMetadataAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}");
        }

        var fileInfo = new FileInfo(filePath);
        var checksum = await ComputeFileChecksumAsync(filePath, cancellationToken).ConfigureAwait(false);

        return new FileMetadata(
            FilePath: filePath,
            Size: fileInfo.Length,
            CreatedAt: fileInfo.CreationTime,
            ModifiedAt: fileInfo.LastWriteTime,
            LastAccessedAt: fileInfo.LastAccessTime,
            IsReadOnly: fileInfo.IsReadOnly,
            Checksum: checksum
        );
    }

    /// <inheritdoc />
    public async Task CreateBackupAsync(string filePath, string backupPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentException.ThrowIfNullOrEmpty(backupPath);

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Source file not found: {filePath}");
        }

        // Ensure backup directory exists
        var backupDirectory = Path.GetDirectoryName(backupPath);
        if (!string.IsNullOrEmpty(backupDirectory) && !Directory.Exists(backupDirectory))
        {
            Directory.CreateDirectory(backupDirectory);
        }

        using var sourceStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var backupStream = new FileStream(backupPath, FileMode.Create, FileAccess.Write, FileShare.None);
        
        await sourceStream.CopyToAsync(backupStream, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> ValidateFileIntegrityAsync(string filePath, string? expectedChecksum = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);

        if (!File.Exists(filePath))
        {
            return false;
        }

        try
        {
            var actualChecksum = await ComputeFileChecksumAsync(filePath, cancellationToken).ConfigureAwait(false);
            
            if (expectedChecksum is null)
            {
                // If no expected checksum provided, just verify the file is readable
                return !string.IsNullOrEmpty(actualChecksum);
            }

            return string.Equals(actualChecksum, expectedChecksum, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> FindFilesAsync(string directoryPath, string searchPattern, bool includeSubdirectories = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(directoryPath);
        ArgumentException.ThrowIfNullOrEmpty(searchPattern);

        if (!Directory.Exists(directoryPath))
        {
            return Enumerable.Empty<string>();
        }

        var searchOption = includeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        
        try
        {
            return Directory.GetFiles(directoryPath, searchPattern, searchOption);
        }
        catch (Exception)
        {
            return Enumerable.Empty<string>();
        }
    }

    /// <summary>
    /// Gets or creates a virtual file reader for the specified file path.
    /// </summary>
    private async Task<IVirtualFileReader> GetOrCreateReaderAsync(string filePath, CancellationToken cancellationToken)
    {
        if (_readerCache.TryGetValue(filePath, out var existingReader))
        {
            return existingReader;
        }

        await _cacheSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring the lock
            if (_readerCache.TryGetValue(filePath, out existingReader))
            {
                return existingReader;
            }

            // Create new reader directly to avoid circular dependency
            // We'll create a simple file stream reader instead to avoid the Services dependency
            var reader = new FileStreamVirtualReader(filePath);
            
            // Manage cache size
            if (_readerCache.Count >= _maxCacheSize)
            {
                // Remove oldest entries (simplified LRU)
                var keysToRemove = _readerCache.Keys.Take(_readerCache.Count - _maxCacheSize + 1).ToList();
                foreach (var key in keysToRemove)
                {
                    if (_readerCache.TryRemove(key, out var oldReader))
                    {
                        oldReader.Dispose();
                    }
                }
            }

            _readerCache.TryAdd(filePath, reader);
            return reader;
        }
        finally
        {
            _cacheSemaphore.Release();
        }
    }

    /// <summary>
    /// Computes the SHA-256 checksum of a file.
    /// </summary>
    private static async Task<string> ComputeFileChecksumAsync(string filePath, CancellationToken cancellationToken)
    {
        using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha256 = SHA256.Create();
        
        var hashBytes = await sha256.ComputeHashAsync(fileStream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hashBytes);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Dispose all cached readers
        foreach (var reader in _readerCache.Values)
        {
            reader.Dispose();
        }
        
        _readerCache.Clear();
        _entityCache.Clear();
        _cacheSemaphore.Dispose();
        
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}