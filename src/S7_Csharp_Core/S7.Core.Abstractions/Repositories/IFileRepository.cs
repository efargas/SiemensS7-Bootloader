using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Models;

namespace S7.Core.Abstractions.Repositories;

/// <summary>
/// Specialized repository interface for file-based data operations.
/// Extends the generic repository pattern with file-specific operations for the S7 bootloader project.
/// </summary>
public interface IFileRepository : IRepository<FileEntity, string>
{
    /// <summary>
    /// Reads a page of data from a file at the specified page index.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="pageIndex">The zero-based page index to read</param>
    /// <param name="pageSize">The size of each page in bytes</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A page containing the requested data</returns>
    Task<Page> ReadPageAsync(string filePath, long pageIndex, int pageSize, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads multiple pages from a file in a single operation.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="pageIndices">The page indices to read</param>
    /// <param name="pageSize">The size of each page in bytes</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A collection of pages containing the requested data</returns>
    Task<IEnumerable<Page>> ReadPagesAsync(string filePath, IEnumerable<long> pageIndices, int pageSize, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes a page of data to a file at the specified page index.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="page">The page data to write</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task WritePageAsync(string filePath, Page page, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes multiple pages to a file in a single operation.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="pages">The pages to write</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task WritePagesAsync(string filePath, IEnumerable<Page> pages, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the total length of a file in bytes.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The file length in bytes</returns>
    Task<long> GetFileLengthAsync(string filePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets file metadata including size, creation time, and modification time.
    /// </summary>
    /// <param name="filePath">The path to the file</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>File metadata information</returns>
    Task<FileMetadata> GetFileMetadataAsync(string filePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a backup copy of a file before modification.
    /// </summary>
    /// <param name="filePath">The path to the file to backup</param>
    /// <param name="backupPath">The path where the backup should be created</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task CreateBackupAsync(string filePath, string backupPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the integrity of a file using checksums or other validation methods.
    /// </summary>
    /// <param name="filePath">The path to the file to validate</param>
    /// <param name="expectedChecksum">The expected checksum for validation</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>True if the file is valid, false otherwise</returns>
    Task<bool> ValidateFileIntegrityAsync(string filePath, string? expectedChecksum = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Searches for files matching the specified pattern.
    /// </summary>
    /// <param name="directoryPath">The directory to search in</param>
    /// <param name="searchPattern">The search pattern (e.g., "*.bin", "dump_*")</param>
    /// <param name="includeSubdirectories">Whether to include subdirectories in the search</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A collection of file paths matching the pattern</returns>
    Task<IEnumerable<string>> FindFilesAsync(string directoryPath, string searchPattern, bool includeSubdirectories = false, CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents a file entity in the repository.
/// </summary>
public record FileEntity(
    string FilePath,
    long Size,
    DateTime CreatedAt,
    DateTime ModifiedAt,
    string? Checksum = null,
    Dictionary<string, object>? Metadata = null)
{
    /// <summary>
    /// Gets the file name without the directory path.
    /// </summary>
    public string FileName => Path.GetFileName(FilePath);

    /// <summary>
    /// Gets the file extension.
    /// </summary>
    public string Extension => Path.GetExtension(FilePath);

    /// <summary>
    /// Gets the directory path containing the file.
    /// </summary>
    public string DirectoryPath => Path.GetDirectoryName(FilePath) ?? string.Empty;
}

/// <summary>
/// Contains metadata information about a file.
/// </summary>
public record FileMetadata(
    string FilePath,
    long Size,
    DateTime CreatedAt,
    DateTime ModifiedAt,
    DateTime LastAccessedAt,
    bool IsReadOnly,
    string? Checksum = null,
    Dictionary<string, object>? ExtendedAttributes = null);