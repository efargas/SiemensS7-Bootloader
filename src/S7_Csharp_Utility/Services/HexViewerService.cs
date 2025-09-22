using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for optimized hex viewing operations with support for large files.
    /// Provides asynchronous file processing, chunked reading, and data analysis.
    /// </summary>
    public sealed class HexViewerService
    {
        private const int DefaultChunkSize = 64 * 1024; // 64KB chunks
        private const int HexBytesPerLine = 16;
        private const int MaxPreviewRows = 10000; // Limit rows for performance

        /// <summary>
        /// Represents a hex row with address, per-byte hex values, and ASCII representation.
        /// Also includes offsets for each byte to support inspector selection.
        /// </summary>
        public sealed class HexRow
        {
            public string Address { get; init; } = string.Empty;
            public string Ascii { get; init; } = string.Empty;
            public long ByteOffset { get; init; }
            public byte[] RawBytes { get; init; } = Array.Empty<byte>();
            // 16 hex strings ("XX") and their corresponding absolute offsets (or -1 for padding)
            public string[] Bytes { get; init; } = new string[HexBytesPerLine];
            public long[] Offsets { get; init; } = new long[HexBytesPerLine];
        }

        /// <summary>
        /// Represents file information for hex viewing.
        /// </summary>
        public sealed class HexFileInfo
        {
            public string FilePath { get; init; } = string.Empty;
            public string FileName { get; init; } = string.Empty;
            public long FileSize { get; init; }
            public string MD5Hash { get; init; } = string.Empty;
            public DateTime LastModified { get; init; }
            public string FormattedSize { get; init; } = string.Empty;
            public string FileType { get; init; } = string.Empty;
        }

        /// <summary>
        /// Represents a chunk of hex data for virtual loading.
        /// </summary>
        public sealed class HexChunk
        {
            public long StartOffset { get; init; }
            public long EndOffset { get; init; }
            public List<HexRow> Rows { get; init; } = new();
            public bool IsLoaded { get; set; }
        }

        /// <summary>
        /// Gets file information including MD5 hash and metadata.
        /// </summary>
        public async Task<HexFileInfo> GetFileInfoAsync(string filePath, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            var fileInfo = new FileInfo(filePath);
            var md5Hash = await ComputeMD5HashAsync(filePath, cancellationToken, progress).ConfigureAwait(false);
            var fileType = DetectFileType(filePath);

            return new HexFileInfo
            {
                FilePath = filePath,
                FileName = fileInfo.Name,
                FileSize = fileInfo.Length,
                MD5Hash = md5Hash,
                LastModified = fileInfo.LastWriteTime,
                FormattedSize = FormatFileSize(fileInfo.Length),
                FileType = fileType
            };
        }

        /// <summary>
        /// Loads hex data from a file with chunked processing for large files.
        /// </summary>
        public async Task<List<HexRow>> LoadHexDataAsync(string filePath, long startOffset = 0, int maxRows = MaxPreviewRows, CancellationToken cancellationToken = default, IProgress<int>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            var rows = new List<HexRow>();

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, DefaultChunkSize, FileOptions.SequentialScan);
            
            if (startOffset > 0)
            {
                stream.Seek(startOffset, SeekOrigin.Begin);
            }

            var buffer = new byte[DefaultChunkSize];
            var currentOffset = startOffset;
            var rowsLoaded = 0;

            while (rowsLoaded < maxRows && currentOffset < stream.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                var chunkRows = await Task.Run(() => ProcessChunkToHexRows(buffer, bytesRead, currentOffset), cancellationToken).ConfigureAwait(false);
                
                foreach (var row in chunkRows)
                {
                    if (rowsLoaded >= maxRows) break;
                    rows.Add(row);
                    rowsLoaded++;
                }

                currentOffset += bytesRead;
                progress?.Report(rowsLoaded);
            }

            return rows;
        }

        /// <summary>
        /// Searches for a hex pattern in the file.
        /// </summary>
        public async Task<List<long>> SearchHexPatternAsync(string filePath, string hexPattern, int maxResults = 100, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            ArgumentNullException.ThrowIfNull(hexPattern);

            var searchBytes = ParseHexPattern(hexPattern);
            if (searchBytes.Length == 0)
            {
                throw new ArgumentException("Invalid hex pattern", nameof(hexPattern));
            }

            var results = new List<long>();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            
            var fileSize = stream.Length;
            var buffer = new byte[DefaultChunkSize + searchBytes.Length - 1];
            var totalBytesRead = 0L;
            var overlap = searchBytes.Length - 1;

            while (totalBytesRead < fileSize && results.Count < maxResults)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesToRead = Math.Min(buffer.Length, (int)(fileSize - totalBytesRead));
                var bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                var matches = await Task.Run(() => FindPatternInBuffer(buffer, bytesRead, searchBytes, totalBytesRead), cancellationToken).ConfigureAwait(false);
                results.AddRange(matches.Take(maxResults - results.Count));

                // Calculate next position, ensuring we don't go backwards or get stuck
                var nextPosition = totalBytesRead + bytesRead - overlap;
                
                // Ensure we make progress - if we would read the same position, advance by at least 1 byte
                if (nextPosition <= totalBytesRead)
                {
                    nextPosition = totalBytesRead + 1;
                }
                
                totalBytesRead = nextPosition;
                
                // Only seek if we haven't reached the end
                if (totalBytesRead < fileSize)
                {
                    stream.Seek(totalBytesRead, SeekOrigin.Begin);
                }

                progress?.Report(totalBytesRead);
            }

            return results;
        }

        /// <summary>
        /// Searches for SHA1 pattern in the file.
        /// </summary>
        public async Task<List<long>> SearchSha1PatternAsync(string filePath, string sha1Pattern, int maxResults = 100, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            ArgumentNullException.ThrowIfNull(sha1Pattern);

            // SHA1 is 20 bytes (160 bits), so we expect a 40-character hex string
            var cleanPattern = sha1Pattern.Replace(" ", "").Replace("-", "").Replace(":", "").ToUpperInvariant();
            if (cleanPattern.Length != 40)
            {
                throw new ArgumentException("SHA1 pattern must be 40 hex characters (20 bytes)", nameof(sha1Pattern));
            }

            var searchBytes = ParseHexPattern(cleanPattern);
            if (searchBytes.Length != 20)
            {
                throw new ArgumentException("Invalid SHA1 pattern", nameof(sha1Pattern));
            }

            return await SearchHexPatternAsync(filePath, cleanPattern, maxResults, cancellationToken, progress);
        }

        /// <summary>
        /// Represents a search result with context information.
        /// </summary>
        public sealed class SearchResult
        {
            public long Offset { get; init; }
            public string Context { get; init; } = string.Empty;
            public byte[] MatchedBytes { get; init; } = Array.Empty<byte>();
            public string Description { get; init; } = string.Empty;
        }

        /// <summary>
        /// Searches for patterns with enhanced result information.
        /// </summary>
        public async Task<List<SearchResult>> SearchPatternWithContextAsync(string filePath, string pattern, bool isSha1 = false, int maxResults = 100, CancellationToken cancellationToken = default, IProgress<long>? progress = null)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            ArgumentNullException.ThrowIfNull(pattern);

            List<long> offsets;
            byte[] searchBytes;

            if (isSha1)
            {
                offsets = await SearchSha1PatternAsync(filePath, pattern, maxResults, cancellationToken, progress);
                searchBytes = ParseHexPattern(pattern.Replace(" ", "").Replace("-", "").Replace(":", ""));
            }
            else
            {
                offsets = await SearchHexPatternAsync(filePath, pattern, maxResults, cancellationToken, progress);
                searchBytes = ParseHexPattern(pattern);
            }

            var results = new List<SearchResult>();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            foreach (var offset in offsets)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Read context around the match (32 bytes before and after)
                const int contextSize = 32;
                var contextStart = Math.Max(0, offset - contextSize);
                var contextLength = Math.Min(stream.Length - contextStart, contextSize * 2 + searchBytes.Length);

                stream.Seek(contextStart, SeekOrigin.Begin);
                var contextBuffer = new byte[contextLength];
                var bytesRead = await stream.ReadAsync(contextBuffer, 0, (int)contextLength, cancellationToken);

                // Create hex context string
                var contextHex = Convert.ToHexString(contextBuffer, 0, bytesRead);
                var formattedContext = string.Join(" ", Enumerable.Range(0, bytesRead)
                    .Select(i => contextHex.Substring(i * 2, 2)));

                // Extract the matched bytes
                var matchStart = (int)(offset - contextStart);
                var matchedBytes = new byte[searchBytes.Length];
                if (matchStart >= 0 && matchStart + searchBytes.Length <= bytesRead)
                {
                    Array.Copy(contextBuffer, matchStart, matchedBytes, 0, searchBytes.Length);
                }

                var description = isSha1 ? "SHA1 Hash" : "Hex Pattern";

                results.Add(new SearchResult
                {
                    Offset = offset,
                    Context = formattedContext,
                    MatchedBytes = matchedBytes,
                    Description = description
                });
            }

            return results;
        }

        /// <summary>
        /// Analyzes data at a specific offset for the data inspector.
        /// </summary>
        public async Task<Dictionary<string, object>> AnalyzeDataAsync(string filePath, long offset, int length = 16, bool isLittleEndian = true, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            var result = new Dictionary<string, object>();

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            
            if (offset >= stream.Length)
            {
                return result;
            }

            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[Math.Min(length, (int)(stream.Length - offset))];
            var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);

            if (bytesRead == 0)
            {
                return result;
            }

            return await Task.Run(() => AnalyzeBytes(buffer, bytesRead, isLittleEndian), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Computes MD5 hash of a file asynchronously.
        /// </summary>
        private async Task<string> ComputeMD5HashAsync(string filePath, CancellationToken cancellationToken, IProgress<long>? progress)
        {
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
        /// Processes a chunk of bytes into hex rows with per-byte columns.
        /// </summary>
        private static List<HexRow> ProcessChunkToHexRows(byte[] buffer, int length, long baseOffset)
        {
            var rows = new List<HexRow>();

            for (int i = 0; i < length; i += HexBytesPerLine)
            {
                var rowLength = Math.Min(HexBytesPerLine, length - i);
                var rowBytes = new byte[rowLength];
                Array.Copy(buffer, i, rowBytes, 0, rowLength);

                var asciiString = new StringBuilder();
                var bytesArray = new string[HexBytesPerLine];
                var offsetsArray = new long[HexBytesPerLine];

                for (int j = 0; j < HexBytesPerLine; j++)
                {
                    if (j < rowLength)
                    {
                        var b = rowBytes[j];
                        bytesArray[j] = b.ToString("X2");
                        offsetsArray[j] = baseOffset + i + j;
                        asciiString.Append(char.IsControl((char)b) ? '.' : (char)b);
                    }
                    else
                    {
                        bytesArray[j] = string.Empty;
                        offsetsArray[j] = -1L;
                        asciiString.Append(' ');
                    }
                }

                rows.Add(new HexRow
                {
                    Address = $"{baseOffset + i:X8}",
                    Ascii = asciiString.ToString(),
                    ByteOffset = baseOffset + i,
                    RawBytes = rowBytes,
                    Bytes = bytesArray,
                    Offsets = offsetsArray
                });
            }

            return rows;
        }

        /// <summary>
        /// Parses a hex pattern string into bytes.
        /// </summary>
        private static byte[] ParseHexPattern(string hexPattern)
        {
            var cleanPattern = hexPattern.Replace(" ", "").Replace("-", "").ToUpperInvariant();
            var bytes = new List<byte>();

            for (int i = 0; i < cleanPattern.Length; i += 2)
            {
                if (i + 1 < cleanPattern.Length)
                {
                    if (byte.TryParse(cleanPattern.Substring(i, 2), System.Globalization.NumberStyles.HexNumber, null, out byte b))
                    {
                        bytes.Add(b);
                    }
                    else
                    {
                        return Array.Empty<byte>();
                    }
                }
            }

            return bytes.ToArray();
        }

        /// <summary>
        /// Finds pattern matches in a buffer.
        /// </summary>
        private static List<long> FindPatternInBuffer(byte[] buffer, int length, byte[] pattern, long baseOffset)
        {
            var matches = new List<long>();

            for (int i = 0; i <= length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    matches.Add(baseOffset + i);
                }
            }

            return matches;
        }

        /// <summary>
        /// Analyzes bytes for the data inspector.
        /// </summary>
        private static Dictionary<string, object> AnalyzeBytes(byte[] buffer, int length, bool isLittleEndian)
        {
            var result = new Dictionary<string, object>();

            if (length == 0)
            {
                return result;
            }

            // String representations
            result["ASCII"] = Encoding.ASCII.GetString(buffer, 0, length);
            result["UTF8"] = Encoding.UTF8.GetString(buffer, 0, length);
            result["Char"] = length > 0 ? ((char)buffer[0]).ToString() : string.Empty;

            // Single byte values
            result["Int8"] = length >= 1 ? (sbyte)buffer[0] : (sbyte)0;
            result["UInt8"] = length >= 1 ? buffer[0] : (byte)0;

            // Multi-byte values
            if (length >= 2)
            {
                var word = GetBytes(buffer, 0, 2, isLittleEndian);
                result["Int16"] = BitConverter.ToInt16(word, 0);
                result["UInt16"] = BitConverter.ToUInt16(word, 0);
            }

            if (length >= 4)
            {
                var dword = GetBytes(buffer, 0, 4, isLittleEndian);
                result["Int32"] = BitConverter.ToInt32(dword, 0);
                result["UInt32"] = BitConverter.ToUInt32(dword, 0);
                result["Float"] = BitConverter.ToSingle(dword, 0);
            }

            if (length >= 8)
            {
                var qword = GetBytes(buffer, 0, 8, isLittleEndian);
                result["Int64"] = BitConverter.ToInt64(qword, 0);
                result["UInt64"] = BitConverter.ToUInt64(qword, 0);
                result["Double"] = BitConverter.ToDouble(qword, 0);
            }

            return result;
        }

        private static byte[] GetBytes(byte[] source, int startIndex, int length, bool isLittleEndian)
        {
            var segment = new byte[length];
            Array.Copy(source, startIndex, segment, 0, length);
            if (!isLittleEndian)
            {
                Array.Reverse(segment);
            }
            return segment;
        }

        /// <summary>
        /// Detects file type based on file extension and magic bytes.
        /// </summary>
        private static string DetectFileType(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            
            return extension switch
            {
                ".exe" => "Executable",
                ".dll" => "Dynamic Library",
                ".bin" => "Binary",
                ".hex" => "Intel HEX",
                ".ihex" => "Intel HEX",
                ".txt" => "Text",
                ".log" => "Log File",
                ".dat" => "Data File",
                ".img" => "Image/Binary",
                ".rom" => "ROM Image",
                ".fw" => "Firmware",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Formats a file size in bytes to a human-readable string.
        /// </summary>
        private static string FormatFileSize(long bytes)
        {
            if (bytes == 0) return "0 B";
            
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;
            
            while (Math.Round(number / 1024) >= 1 && counter < suffixes.Length - 1)
            {
                number /= 1024;
                counter++;
            }
            
            return $"{number:n1} {suffixes[counter]}";
        }
    }
}