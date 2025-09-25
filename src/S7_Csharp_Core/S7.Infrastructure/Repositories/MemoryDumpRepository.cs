using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Repositories;
using S7.Utils.Interfaces;

namespace S7.Infrastructure.Repositories;

/// <summary>
/// Memory dump repository implementation that provides specialized operations for PLC memory dumps.
/// Integrates with the file repository infrastructure while adding memory-specific functionality.
/// </summary>
public class MemoryDumpRepository : IMemoryDumpRepository
{
    private readonly IFileRepository _fileRepository;
    private readonly ConcurrentDictionary<string, MemoryDump> _dumpCache;
    private readonly ConcurrentDictionary<string, IVirtualFileReader> _readerCache;
    private readonly SemaphoreSlim _cacheSemaphore;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the MemoryDumpRepository class.
    /// </summary>
    /// <param name="fileRepository">The underlying file repository for file operations</param>
    public MemoryDumpRepository(IFileRepository fileRepository)
    {
        _fileRepository = fileRepository ?? throw new ArgumentNullException(nameof(fileRepository));
        _dumpCache = new ConcurrentDictionary<string, MemoryDump>();
        _readerCache = new ConcurrentDictionary<string, IVirtualFileReader>();
        _cacheSemaphore = new SemaphoreSlim(1, 1);
    }

    /// <inheritdoc />
    public async Task<MemoryDump?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        if (_dumpCache.TryGetValue(id, out var cachedDump))
        {
            return cachedDump;
        }

        // Try to load from file system
        var fileEntity = await _fileRepository.GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
        if (fileEntity is null)
        {
            return null;
        }

        // Create memory dump from file entity
        var metadata = await ExtractMetadataFromFileAsync(id, cancellationToken).ConfigureAwait(false);
        var dump = new MemoryDump(
            Id: id,
            FilePath: id,
            Metadata: metadata,
            CreatedAt: fileEntity.CreatedAt,
            ModifiedAt: fileEntity.ModifiedAt,
            Size: fileEntity.Size,
            Checksum: fileEntity.Checksum
        );

        _dumpCache.TryAdd(id, dump);
        return dump;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<MemoryDump>> FindAsync(Expression<Func<MemoryDump, bool>> predicate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        var allDumps = _dumpCache.Values.ToList();
        var compiledPredicate = predicate.Compile();
        return allDumps.Where(compiledPredicate);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<MemoryDump>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return _dumpCache.Values.ToList();
    }

    /// <inheritdoc />
    public async Task<MemoryDump> AddAsync(MemoryDump entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);

        // Ensure the underlying file is tracked
        var fileEntity = new FileEntity(
            FilePath: entity.FilePath,
            Size: entity.Size,
            CreatedAt: entity.CreatedAt,
            ModifiedAt: entity.ModifiedAt,
            Checksum: entity.Checksum
        );

        await _fileRepository.AddAsync(fileEntity, cancellationToken).ConfigureAwait(false);
        _dumpCache.TryAdd(entity.Id, entity);
        
        return entity;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<MemoryDump>> AddRangeAsync(IEnumerable<MemoryDump> entities, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entities);

        var addedDumps = new List<MemoryDump>();
        foreach (var entity in entities)
        {
            var added = await AddAsync(entity, cancellationToken).ConfigureAwait(false);
            addedDumps.Add(added);
        }

        return addedDumps;
    }

    /// <inheritdoc />
    public async Task<MemoryDump> UpdateAsync(MemoryDump entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);

        _dumpCache.AddOrUpdate(entity.Id, entity, (key, oldValue) => entity);
        
        // Update underlying file entity
        var fileEntity = new FileEntity(
            FilePath: entity.FilePath,
            Size: entity.Size,
            CreatedAt: entity.CreatedAt,
            ModifiedAt: entity.ModifiedAt,
            Checksum: entity.Checksum
        );

        await _fileRepository.UpdateAsync(fileEntity, cancellationToken).ConfigureAwait(false);
        
        // Invalidate reader cache
        if (_readerCache.TryRemove(entity.Id, out var reader))
        {
            reader.Dispose();
        }

        return entity;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        var success = await _fileRepository.DeleteAsync(id, cancellationToken).ConfigureAwait(false);
        if (success)
        {
            _dumpCache.TryRemove(id, out _);
            if (_readerCache.TryRemove(id, out var reader))
            {
                reader.Dispose();
            }
        }

        return success;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(MemoryDump entity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entity);
        return await DeleteAsync(entity.Id, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return await _fileRepository.ExistsAsync(id, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<long> CountAsync(CancellationToken cancellationToken = default)
    {
        return _dumpCache.Count;
    }

    /// <inheritdoc />
    public async Task<long> CountAsync(Expression<Func<MemoryDump, bool>> predicate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        
        var dumps = await FindAsync(predicate, cancellationToken).ConfigureAwait(false);
        return dumps.LongCount();
    }

    /// <inheritdoc />
    public async Task<MemoryDump> CreateMemoryDumpAsync(string sourceFilePath, MemoryDumpMetadata dumpMetadata, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sourceFilePath);
        ArgumentNullException.ThrowIfNull(dumpMetadata);

        if (!File.Exists(sourceFilePath))
        {
            throw new FileNotFoundException($"Source file not found: {sourceFilePath}");
        }

        var fileInfo = new FileInfo(sourceFilePath);
        var checksum = await ComputeFileChecksumAsync(sourceFilePath, cancellationToken).ConfigureAwait(false);

        var dump = new MemoryDump(
            Id: sourceFilePath,
            FilePath: sourceFilePath,
            Metadata: dumpMetadata,
            CreatedAt: fileInfo.CreationTime,
            ModifiedAt: fileInfo.LastWriteTime,
            Size: fileInfo.Length,
            Checksum: checksum
        );

        return await AddAsync(dump, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ReadOnlyMemory<byte>> ReadMemoryRegionAsync(string dumpId, long startAddress, int length, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);
        ArgumentOutOfRangeException.ThrowIfNegative(startAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
        if (dump is null)
        {
            throw new ArgumentException($"Memory dump not found: {dumpId}");
        }

        var reader = await GetOrCreateReaderAsync(dumpId, cancellationToken).ConfigureAwait(false);
        
        // Calculate relative offset from base address
        var relativeOffset = startAddress - dump.BaseAddress;
        if (relativeOffset < 0 || relativeOffset >= dump.Size)
        {
            throw new ArgumentOutOfRangeException(nameof(startAddress), "Address is outside the memory dump range");
        }

        // Read data using page-based approach
        var pageSize = reader.PageSize;
        var startPage = relativeOffset / pageSize;
        var endPage = (relativeOffset + length - 1) / pageSize;
        
        var buffer = new byte[length];
        var bufferOffset = 0;

        for (var pageIndex = startPage; pageIndex <= endPage; pageIndex++)
        {
            var page = await reader.ReadPageAsync(pageIndex, pageSize, cancellationToken).ConfigureAwait(false);
            
            var pageStartOffset = pageIndex * pageSize;
            var copyStartInPage = Math.Max(0, (int)(relativeOffset - pageStartOffset));
            var copyEndInPage = Math.Min(page.Length, (int)(relativeOffset + length - pageStartOffset));
            var copyLength = copyEndInPage - copyStartInPage;

            if (copyLength > 0)
            {
                var pageArray = page.Data.ToArray();
                Array.Copy(pageArray, copyStartInPage, buffer, bufferOffset, copyLength);
                bufferOffset += copyLength;
            }
        }

        return new ReadOnlyMemory<byte>(buffer);
    }

    /// <inheritdoc />
    public async Task WriteMemoryRegionAsync(string dumpId, long startAddress, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);
        ArgumentOutOfRangeException.ThrowIfNegative(startAddress);

        var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
        if (dump is null)
        {
            throw new ArgumentException($"Memory dump not found: {dumpId}");
        }

        // Calculate relative offset from base address
        var relativeOffset = startAddress - dump.BaseAddress;
        if (relativeOffset < 0 || relativeOffset >= dump.Size)
        {
            throw new ArgumentOutOfRangeException(nameof(startAddress), "Address is outside the memory dump range");
        }

        // Write data directly to file
        using var fileStream = new FileStream(dump.FilePath, FileMode.Open, FileAccess.Write, FileShare.Read);
        fileStream.Seek(relativeOffset, SeekOrigin.Begin);
        await fileStream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate caches
        if (_readerCache.TryRemove(dumpId, out var reader))
        {
            reader.Dispose();
        }

        // Update dump metadata
        var updatedDump = dump with 
        { 
            ModifiedAt = DateTime.UtcNow,
            Checksum = null // Will be recomputed on next access
        };
        _dumpCache.TryUpdate(dumpId, updatedDump, dump);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<MemoryDifference>> CompareMemoryDumpsAsync(string firstDumpId, string secondDumpId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(firstDumpId);
        ArgumentException.ThrowIfNullOrEmpty(secondDumpId);

        var firstDump = await GetByIdAsync(firstDumpId, cancellationToken).ConfigureAwait(false);
        var secondDump = await GetByIdAsync(secondDumpId, cancellationToken).ConfigureAwait(false);

        if (firstDump is null)
        {
            throw new ArgumentException($"First memory dump not found: {firstDumpId}");
        }

        if (secondDump is null)
        {
            throw new ArgumentException($"Second memory dump not found: {secondDumpId}");
        }

        var differences = new List<MemoryDifference>();
        var compareSize = Math.Min(firstDump.Size, secondDump.Size);
        
        const int chunkSize = 64 * 1024; // 64KB chunks
        
        for (long offset = 0; offset < compareSize; offset += chunkSize)
        {
            var currentChunkSize = (int)Math.Min(chunkSize, compareSize - offset);
            var address = firstDump.BaseAddress + offset;
            
            var firstData = await ReadMemoryRegionAsync(firstDumpId, address, currentChunkSize, cancellationToken).ConfigureAwait(false);
            var secondData = await ReadMemoryRegionAsync(secondDumpId, address, currentChunkSize, cancellationToken).ConfigureAwait(false);

            var firstArray = firstData.ToArray();
            var secondArray = secondData.ToArray();

            for (int i = 0; i < Math.Min(firstArray.Length, secondArray.Length); i++)
            {
                if (firstArray[i] != secondArray[i])
                {
                    differences.Add(new MemoryDifference(
                        Address: address + i,
                        OriginalValue: firstArray[i],
                        NewValue: secondArray[i],
                        Description: $"Byte difference at address 0x{address + i:X8}"
                    ));
                }
            }
        }

        return differences;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<long>> SearchPatternAsync(string dumpId, ReadOnlyMemory<byte> pattern, long? startAddress = null, long? endAddress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);
        
        if (pattern.Length == 0)
        {
            return Enumerable.Empty<long>();
        }

        var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
        if (dump is null)
        {
            throw new ArgumentException($"Memory dump not found: {dumpId}");
        }

        var searchStart = startAddress ?? dump.BaseAddress;
        var searchEnd = endAddress ?? dump.EndAddress;
        
        if (searchStart < dump.BaseAddress || searchEnd > dump.EndAddress)
        {
            throw new ArgumentOutOfRangeException("Search range is outside the memory dump bounds");
        }

        var matches = new List<long>();
        var patternBytes = pattern.ToArray();
        const int chunkSize = 64 * 1024; // 64KB chunks with overlap
        var overlap = patternBytes.Length - 1;

        for (var address = searchStart; address <= searchEnd - patternBytes.Length; address += chunkSize - overlap)
        {
            var readSize = (int)Math.Min(chunkSize, searchEnd - address + 1);
            var data = await ReadMemoryRegionAsync(dumpId, address, readSize, cancellationToken).ConfigureAwait(false);
            var dataArray = data.ToArray();

            // Boyer-Moore-like search within the chunk
            for (int i = 0; i <= dataArray.Length - patternBytes.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < patternBytes.Length; j++)
                {
                    if (dataArray[i + j] != patternBytes[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    matches.Add(address + i);
                }
            }
        }

        return matches;
    }

    /// <inheritdoc />
    public async Task ExtractMemorySegmentAsync(string dumpId, long startAddress, int length, string outputPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentOutOfRangeException.ThrowIfNegative(startAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        var data = await ReadMemoryRegionAsync(dumpId, startAddress, length, cancellationToken).ConfigureAwait(false);
        
        // Ensure output directory exists
        var outputDirectory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDirectory) && !Directory.Exists(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await outputStream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<MemoryDumpValidationResult> ValidateDumpIntegrityAsync(string dumpId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);

        try
        {
            var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
            if (dump is null)
            {
                return new MemoryDumpValidationResult(
                    IsValid: false,
                    ErrorMessage: $"Memory dump not found: {dumpId}"
                );
            }

            var isFileValid = await _fileRepository.ValidateFileIntegrityAsync(dump.FilePath, dump.Checksum, cancellationToken).ConfigureAwait(false);
            if (!isFileValid)
            {
                return new MemoryDumpValidationResult(
                    IsValid: false,
                    ErrorMessage: "File integrity check failed - checksum mismatch"
                );
            }

            // Additional validation checks could be added here
            var warnings = new List<string>();
            
            if (dump.Size == 0)
            {
                warnings.Add("Memory dump is empty");
            }

            if (dump.Metadata.BaseAddress < 0)
            {
                warnings.Add("Base address is negative");
            }

            return new MemoryDumpValidationResult(
                IsValid: true,
                Warnings: warnings.Any() ? warnings : null
            );
        }
        catch (Exception ex)
        {
            return new MemoryDumpValidationResult(
                IsValid: false,
                ErrorMessage: $"Validation failed: {ex.Message}"
            );
        }
    }

    /// <inheritdoc />
    public async Task<MemoryDumpStatistics> GetDumpStatisticsAsync(string dumpId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);

        var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
        if (dump is null)
        {
            throw new ArgumentException($"Memory dump not found: {dumpId}");
        }

        var byteFrequency = new Dictionary<byte, long>();
        var regions = new List<MemoryRegion>();
        
        // Analyze the dump in chunks
        const int chunkSize = 64 * 1024;
        
        for (long offset = 0; offset < dump.Size; offset += chunkSize)
        {
            var currentChunkSize = (int)Math.Min(chunkSize, dump.Size - offset);
            var address = dump.BaseAddress + offset;
            
            var data = await ReadMemoryRegionAsync(dumpId, address, currentChunkSize, cancellationToken).ConfigureAwait(false);
            var dataArray = data.ToArray();

            // Count byte frequencies
            foreach (var b in dataArray)
            {
                byteFrequency[b] = byteFrequency.GetValueOrDefault(b, 0) + 1;
            }
        }

        // Simple region identification (could be enhanced)
        regions.Add(new MemoryRegion(
            StartAddress: dump.BaseAddress,
            EndAddress: dump.EndAddress,
            RegionType: "Data",
            Description: "Memory dump data region"
        ));

        return new MemoryDumpStatistics(
            TotalSize: dump.Size,
            BaseAddress: dump.BaseAddress,
            EndAddress: dump.EndAddress,
            UniqueByteValues: byteFrequency.Count,
            ByteFrequency: byteFrequency,
            IdentifiedRegions: regions
        );
    }

    /// <inheritdoc />
    public async Task CreateDumpIndexAsync(string dumpId, MemoryDumpIndexOptions? indexOptions = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(dumpId);

        var options = indexOptions ?? new MemoryDumpIndexOptions();
        var dump = await GetByIdAsync(dumpId, cancellationToken).ConfigureAwait(false);
        
        if (dump is null)
        {
            throw new ArgumentException($"Memory dump not found: {dumpId}");
        }

        // Create index file path
        var indexPath = dump.FilePath + ".index";
        
        // This is a simplified index creation - in production, you'd want a more sophisticated indexing system
        var indexData = new Dictionary<string, object>
        {
            ["DumpId"] = dumpId,
            ["BaseAddress"] = dump.BaseAddress,
            ["Size"] = dump.Size,
            ["CreatedAt"] = DateTime.UtcNow,
            ["IndexOptions"] = options
        };

        // Save index to file (simplified JSON serialization)
        var indexJson = System.Text.Json.JsonSerializer.Serialize(indexData, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(indexPath, indexJson, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets or creates a virtual file reader for the specified dump.
    /// </summary>
    private async Task<IVirtualFileReader> GetOrCreateReaderAsync(string dumpId, CancellationToken cancellationToken)
    {
        if (_readerCache.TryGetValue(dumpId, out var existingReader))
        {
            return existingReader;
        }

        await _cacheSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring the lock
            if (_readerCache.TryGetValue(dumpId, out existingReader))
            {
                return existingReader;
            }

            var reader = new FileStreamVirtualReader(dumpId);
            _readerCache.TryAdd(dumpId, reader);
            return reader;
        }
        finally
        {
            _cacheSemaphore.Release();
        }
    }

    /// <summary>
    /// Extracts metadata from a memory dump file.
    /// </summary>
    private static async Task<MemoryDumpMetadata> ExtractMetadataFromFileAsync(string filePath, CancellationToken cancellationToken)
    {
        // This is a simplified metadata extraction - in production, you'd parse actual dump headers
        var fileInfo = new FileInfo(filePath);
        
        return new MemoryDumpMetadata(
            BaseAddress: 0x00000000, // Default base address
            DeviceInfo: "Unknown Device",
            FirmwareVersion: "Unknown",
            DumpTimestamp: fileInfo.CreationTime
        );
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
        _dumpCache.Clear();
        _cacheSemaphore.Dispose();
        _fileRepository.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}