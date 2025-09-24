using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net
{
    /// <summary>
    /// Represents information about a discovered payload.
    /// </summary>
    public class PayloadInfo
    {
        public string Name { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Type { get; set; } = string.Empty;
    }

    /// <summary>
    /// Manages loading payloads from the file system.
    /// </summary>
    public class PayloadManager
    {
        private readonly string _baseDirectory;

        /// <summary>
        /// Initializes a new instance of the <see cref="PayloadManager"/> class.
        /// </summary>
        /// <param name="baseDirectory">The base directory where payloads are stored.</param>
        public PayloadManager(string baseDirectory)
        {
            _baseDirectory = baseDirectory;
        }

        /// <summary>
        /// Asynchronously scans the payloads directory and returns information about all discovered payloads.
        /// </summary>
        /// <param name="payloadsBase">The base directory to scan for payloads.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A list of discovered payload information.</returns>
        public Task<List<PayloadInfo>> ScanPayloadsAsync(string payloadsBase, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var payloads = new List<PayloadInfo>();

                if (!Directory.Exists(payloadsBase))
                {
                    return payloads; // Return empty list if directory doesn't exist
                }

                try
                {
                    // Look for common payload file patterns
                    var payloadPatterns = new[]
                    {
                        "*.bin",
                        "stager*",
                        "dump_mem*",
                        "hello_*",
                        "tic_tac_toe*"
                    };

                    var foundFiles = new HashSet<string>();

                    foreach (var pattern in payloadPatterns)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        foreach (var file in Directory.GetFiles(payloadsBase, pattern, SearchOption.AllDirectories))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            if (foundFiles.Add(file)) // Only add if not already found
                            {
                                var fileInfo = new FileInfo(file);
                                var relativePath = Path.GetRelativePath(payloadsBase, file);

                                payloads.Add(new PayloadInfo
                                {
                                    Name = Path.GetFileName(file),
                                    FilePath = file,
                                    RelativePath = relativePath,
                                    Size = fileInfo.Length,
                                    Type = DeterminePayloadType(file)
                                });
                            }
                        }
                    }

                    // Sort by type and then by name
                    payloads.Sort((a, b) =>
                    {
                        var typeComparison = a.Type.CompareTo(b.Type);
                        return typeComparison != 0 ? typeComparison : a.Name.CompareTo(b.Name);
                    });
                }
                catch (OperationCanceledException)
                {
                    // Propagate cancellation
                    throw;
                }
                catch (Exception ex)
                {
                    // Log error but don't throw - return what we found so far
                    System.Diagnostics.Debug.WriteLine($"Error scanning payloads: {ex.Message}");
                }

                return payloads;
            }, cancellationToken);
        }

        /// <summary>
        /// Asynchronously gets the stager payload.
        /// </summary>
        /// <returns>The stager payload as a byte array.</returns>
        public async Task<byte[]> GetStagerPayloadAsync(string payloadsBase)
        {
            var filePath = await FindPayloadFileAsync(payloadsBase, new[] { "stager.bin", "stager" });
            return await File.ReadAllBytesAsync(filePath);
        }

        /// <summary>
        /// Asynchronously gets the memory dumper payload.
        /// </summary>
        /// <returns>The memory dumper payload as a byte array.</returns>
        public async Task<byte[]> GetMemoryDumperPayloadAsync(string payloadsBase)
        {
            var filePath = await FindPayloadFileAsync(payloadsBase, new[] { "dump_mem.bin", "dump_mem" });
            return await File.ReadAllBytesAsync(filePath);
        }

        /// <summary>
        /// Determines the type of payload based on the file name and path.
        /// </summary>
        private static string DeterminePayloadType(string filePath)
        {
            var fileName = Path.GetFileName(filePath).ToLowerInvariant();
            var directory = Path.GetFileName(Path.GetDirectoryName(filePath))?.ToLowerInvariant() ?? "";

            if (fileName.Contains("stager") || directory.Contains("stager"))
                return "Stager";
            if (fileName.Contains("dump_mem") || directory.Contains("dump_mem"))
                return "Memory Dumper";
            if (fileName.Contains("hello") || directory.Contains("hello"))
                return "Hello World";
            if (fileName.Contains("tic_tac_toe") || directory.Contains("tic_tac_toe"))
                return "Tic Tac Toe";
            if (fileName.EndsWith(".bin"))
                return "Binary";
            
            return "Unknown";
        }

        /// <summary>
        /// Asynchronously and recursively searches for the payload file in the base directory.
        /// Tries multiple possible file names in order of preference.
        /// </summary>
        private static Task<string> FindPayloadFileAsync(string payloadsBase, string[] possibleNames)
        {
            return Task.Run(() =>
            {
                if (!Directory.Exists(payloadsBase))
                {
                    throw new DirectoryNotFoundException($"Payloads directory not found: {payloadsBase}. Please check the path configuration.");
                }

                try
                {
                    // Try each possible name in order
                    foreach (var fileName in possibleNames)
                    {
                        var firstFile = Directory.EnumerateFiles(payloadsBase, fileName, SearchOption.AllDirectories).FirstOrDefault();
                        if (firstFile != null)
                        {
                            return firstFile; // Return first match
                        }
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    throw new UnauthorizedAccessException($"Access denied to payloads directory: {payloadsBase}. {ex.Message}");
                }
                catch (DirectoryNotFoundException ex)
                {
                    throw new DirectoryNotFoundException($"Payloads directory not found: {payloadsBase}. {ex.Message}");
                }

                // If we get here, none of the files were found
                var allFiles = Directory.EnumerateFiles(payloadsBase, "*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .ToArray();

                throw new FileNotFoundException($"None of the expected payload files ({string.Join(", ", possibleNames)}) found under {payloadsBase}. Available files: {string.Join(", ", allFiles)}");
            });
        }
    }
}
