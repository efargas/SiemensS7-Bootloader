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
    public enum SearchType { Hex, SHA1, Text }

    public sealed class HexViewerService
    {
        private const int DefaultChunkSize = 64 * 1024;
        private const int HexBytesPerLine = 16;

        public sealed class HexRow
        {
            public string Address { get; init; } = string.Empty;
            public string Ascii { get; init; } = string.Empty;
            public long ByteOffset { get; init; }
            public byte[] RawBytes { get; init; } = Array.Empty<byte>();
            public string[] Bytes { get; init; } = new string[HexBytesPerLine];
            public long[] Offsets { get; init; } = new long[HexBytesPerLine];
        }

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

        public async Task<HexFileInfo> GetFileInfoAsync(string filePath, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            var fileInfo = new FileInfo(filePath);
            var md5Hash = await ComputeMD5HashAsync(filePath, cancellationToken, null).ConfigureAwait(false);
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

        public async Task<Dictionary<string, object>> AnalyzeDataAsync(VirtualizingHexList hexList, long offset, int length = 16, bool isLittleEndian = true, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(hexList);

            var result = new Dictionary<string, object>();

            if (offset >= hexList.FileSize)
            {
                return result;
            }

            var bytesToRead = (int)Math.Min(length, hexList.FileSize - offset);
            var buffer = hexList.ReadRange(offset, bytesToRead);

            if (buffer.Length == 0)
            {
                return result;
            }

            return await Task.Run(() => AnalyzeBytes(buffer, buffer.Length, isLittleEndian), cancellationToken).ConfigureAwait(false);
        }

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

        private static Dictionary<string, object> AnalyzeBytes(byte[] buffer, int length, bool isLittleEndian)
        {
            var result = new Dictionary<string, object>();

            if (length == 0)
            {
                return result;
            }

            result["ASCII"] = Encoding.ASCII.GetString(buffer, 0, length);
            result["UTF8"] = Encoding.UTF8.GetString(buffer, 0, length);
            result["Char"] = length > 0 ? ((char)buffer[0]).ToString() : string.Empty;

            result["Int8"] = length >= 1 ? (sbyte)buffer[0] : (sbyte)0;
            result["UInt8"] = length >= 1 ? buffer[0] : (byte)0;

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

        public async Task SearchAsync(
            VirtualizingHexList hexList,
            string searchText,
            SearchType searchType,
            IProgress<long> progress,
            CancellationToken cancellationToken)
        {
            await Task.Run(() => // ConfigureAwait(false) applied at end of method call
            {
                if (string.IsNullOrEmpty(searchText) || hexList == null)
                {
                    return;
                }

                byte[] pattern;
                try
                {
                    pattern = searchType switch
                    {
                        SearchType.Hex => Convert.FromHexString(searchText.Replace(" ", "").Replace("0x", "")),
                        SearchType.SHA1 => Convert.FromHexString(searchText.Replace(" ", "").Replace("0x", "")),
                        SearchType.Text => Encoding.UTF8.GetBytes(searchText),
                        _ => throw new NotSupportedException($"Search type {searchType} is not supported.")
                    };
                }
                catch (FormatException)
                {
                    return; // Invalid hex, do nothing.
                }

                if (pattern.Length == 0)
                {
                    return;
                }

                foreach (var offset in hexList.Search(pattern, 0, cancellationToken))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    progress.Report(offset);
                }
            }, cancellationToken).ConfigureAwait(false);
        }
    }
}
