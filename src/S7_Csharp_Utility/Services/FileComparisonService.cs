using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for optimized file comparison operations with support for large files.
    /// Provides asynchronous file processing, chunked reading, and hash computation.
    /// </summary>
    public sealed class FileComparisonService
    {
        private const int DefaultChunkSize = 64 * 1024; // 64KB chunks
        private const int HexBytesPerLine = 16;

        /// <summary>
        /// Represents file information including metadata and hash.
        /// </summary>
        public sealed class FileInfo
        {
            public string FilePath { get; init; } = string.Empty;
            public string FileName { get; init; } = string.Empty;
            public long FileSize { get; init; }
            public string MD5Hash { get; init; } = string.Empty;
            public DateTime LastModified { get; init; }
            public string FormattedSize { get; init; } = string.Empty;
        }

        /// <summary>
        /// Represents a chunk of hex-formatted file data.
        /// </summary>
        public sealed class FileChunk
        {
            public long Offset { get; init; }
            public string HexData { get; init; } = string.Empty;
            public int ByteCount { get; init; }
            public bool IsLastChunk { get; init; }
        }

        /// <summary>
        /// Computes file information including MD5 hash asynchronously.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <param name="progress">Progress reporter for hash computation.</param>
        /// <returns>File information including MD5 hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
        public async Task<FileInfo> GetFileInfoAsync(string filePath, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            var fileInfo = new System.IO.FileInfo(filePath);
            var md5Hash = await ComputeMD5HashAsync(filePath, cancellationToken, progress).ConfigureAwait(false);

            return new FileInfo
            {
                FilePath = filePath,
                FileName = fileInfo.Name,
                FileSize = fileInfo.Length,
                MD5Hash = md5Hash,
                LastModified = fileInfo.LastWriteTime,
                FormattedSize = FormatFileSize(fileInfo.Length)
            };
        }

        /// <summary>
        /// Computes MD5 hash of a file asynchronously with progress reporting.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <param name="progress">Progress reporter for bytes processed.</param>
        /// <returns>The MD5 hash as a lowercase hex string.</returns>
        public async Task<string> ComputeMD5HashAsync(string filePath, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            using var md5 = MD5.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, DefaultChunkSize, FileOptions.SequentialScan);
            
            var buffer = new byte[DefaultChunkSize];
            long totalBytesRead = 0;
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                md5.TransformBlock(buffer, 0, bytesRead, null, 0);
                totalBytesRead += bytesRead;
                progress?.Report(totalBytesRead);
            }

            md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(md5.Hash!).ToLowerInvariant();
        }

        /// <summary>
        /// Reads a chunk of file data and converts it to hex format asynchronously.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <param name="offset">The offset to start reading from.</param>
        /// <param name="chunkSize">The size of the chunk to read.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A FileChunk containing the hex-formatted data.</returns>
        public async Task<FileChunk> ReadFileChunkAsync(string filePath, long offset, int chunkSize = DefaultChunkSize, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            
            if (offset >= stream.Length)
            {
                return new FileChunk
                {
                    Offset = offset,
                    HexData = string.Empty,
                    ByteCount = 0,
                    IsLastChunk = true
                };
            }

            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[Math.Min(chunkSize, (int)(stream.Length - offset))];
            var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);

            var hexData = await Task.Run(() => ConvertToHexString(buffer, 0, bytesRead, offset), cancellationToken).ConfigureAwait(false);

            return new FileChunk
            {
                Offset = offset,
                HexData = hexData,
                ByteCount = bytesRead,
                IsLastChunk = offset + bytesRead >= stream.Length
            };
        }

        /// <summary>
        /// Converts byte data to a formatted hex string with addresses and ASCII representation.
        /// </summary>
        /// <param name="data">The byte data to convert.</param>
        /// <param name="startIndex">The starting index in the data array.</param>
        /// <param name="length">The number of bytes to convert.</param>
        /// <param name="baseAddress">The base address for the hex dump.</param>
        /// <returns>A formatted hex string.</returns>
        private static string ConvertToHexString(byte[] data, int startIndex, int length, long baseAddress)
        {
            var sb = new StringBuilder();
            
            for (int i = 0; i < length; i += HexBytesPerLine)
            {
                // Address
                sb.AppendFormat("0x{0:X8}: ", baseAddress + i);
                
                // Hex bytes
                for (int j = 0; j < HexBytesPerLine; j++)
                {
                    if (i + j < length)
                    {
                        sb.AppendFormat("{0:X2} ", data[startIndex + i + j]);
                    }
                    else
                    {
                        sb.Append("   ");
                    }
                }
                
                sb.Append(" | ");
                
                // ASCII representation
                for (int j = 0; j < HexBytesPerLine; j++)
                {
                    if (i + j < length)
                    {
                        char c = (char)data[startIndex + i + j];
                        sb.Append(char.IsControl(c) ? '.' : c);
                    }
                    else
                    {
                        sb.Append(' ');
                    }
                }
                
                sb.AppendLine();
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Formats a file size in bytes to a human-readable string.
        /// </summary>
        /// <param name="bytes">The file size in bytes.</param>
        /// <returns>A formatted file size string.</returns>
        private static string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;
            
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            
            return $"{number:n1} {suffixes[counter]}";
        }

        /// <summary>
        /// Compares two files and determines if they are identical based on size and hash.
        /// </summary>
        /// <param name="file1Path">Path to the first file.</param>
        /// <param name="file2Path">Path to the second file.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>True if files are identical, false otherwise.</returns>
        public async Task<bool> AreFilesIdenticalAsync(string file1Path, string file2Path, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(file1Path);
            ArgumentNullException.ThrowIfNull(file2Path);

            // Quick size check first
            var file1Info = new System.IO.FileInfo(file1Path);
            var file2Info = new System.IO.FileInfo(file2Path);

            if (file1Info.Length != file2Info.Length)
            {
                return false;
            }

            // If sizes are equal, compare hashes
            var hash1Task = ComputeMD5HashAsync(file1Path, cancellationToken);
            var hash2Task = ComputeMD5HashAsync(file2Path, cancellationToken);

            var hashes = await Task.WhenAll(hash1Task, hash2Task).ConfigureAwait(false);
            return string.Equals(hashes[0], hashes[1], StringComparison.OrdinalIgnoreCase);
        }
    }
}