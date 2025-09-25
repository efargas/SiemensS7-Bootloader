using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Infrastructure;

/// <summary>
/// File stream-based virtual file reader implementation.
/// Provides page-based access to files using standard file streams.
/// </summary>
public class FileStreamVirtualReader : IVirtualFileReader
{
    private readonly string _filePath;
    private readonly long _length;
    private readonly int _pageSize;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the FileStreamVirtualReader class.
    /// </summary>
    /// <param name="filePath">The path to the file to read</param>
    /// <param name="pageSize">The preferred page size for reading operations</param>
    public FileStreamVirtualReader(string filePath, int pageSize = 4096)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pageSize);

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}");
        }

        _filePath = filePath;
        _pageSize = pageSize;
        
        var fileInfo = new FileInfo(filePath);
        _length = fileInfo.Length;
    }

    /// <inheritdoc />
    public long Length => _length;

    /// <inheritdoc />
    public int PageSize => _pageSize;

    /// <inheritdoc />
    public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(pageIndex);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pageSize);

        ct.ThrowIfCancellationRequested();

        var offset = pageIndex * pageSize;
        
        if (offset >= _length)
        {
            return new Page(pageIndex, ReadOnlyMemory<byte>.Empty, 0);
        }

        var bytesToRead = (int)Math.Min(pageSize, _length - offset);
        var buffer = new byte[bytesToRead];

        using var fileStream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        fileStream.Seek(offset, SeekOrigin.Begin);
        
        var totalBytesRead = 0;
        while (totalBytesRead < bytesToRead)
        {
            ct.ThrowIfCancellationRequested();
            
            var bytesRead = await fileStream.ReadAsync(
                buffer.AsMemory(totalBytesRead, bytesToRead - totalBytesRead), 
                ct).ConfigureAwait(false);
            
            if (bytesRead == 0)
            {
                // End of file reached
                break;
            }
            
            totalBytesRead += bytesRead;
        }

        var actualData = totalBytesRead == buffer.Length 
            ? new ReadOnlyMemory<byte>(buffer)
            : new ReadOnlyMemory<byte>(buffer, 0, totalBytesRead);

        return new Page(pageIndex, actualData, totalBytesRead);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}