using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Net.Exceptions;

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
        private readonly ILogger<PayloadManager> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="PayloadManager"/> class.
        /// </summary>
        /// <param name="baseDirectory">The base directory where payloads are stored.</param>
        /// <param name="logger">The logger instance.</param>
        public PayloadManager(string baseDirectory, ILogger<PayloadManager> logger)
        {
            _baseDirectory = baseDirectory ?? throw new ArgumentNullException(nameof(baseDirectory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Asynchronously scans the payloads directory and returns information about all discovered payloads.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A list of discovered payload information.</returns>
        public Task<List<PayloadInfo>> ScanPayloadsAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var payloads = new List<PayloadInfo>();

                if (!Directory.Exists(_baseDirectory))
                {
                    _logger.LogWarning("Payloads directory {Directory} does not exist.", _baseDirectory);
                    return payloads;
                }

                try
                {
                    var foundFiles = new HashSet<string>();

                    foreach (var pattern in PayloadConstants.PAYLOAD_PATTERNS)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        foreach (var file in Directory.GetFiles(_baseDirectory, pattern, SearchOption.AllDirectories))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            if (foundFiles.Add(file))
                            {
                                var fileInfo = new FileInfo(file);
                                var relativePath = Path.GetRelativePath(_baseDirectory, file);

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

                    payloads.Sort((a, b) =>
                    {
                        var typeComparison = a.Type.CompareTo(b.Type);
                        return typeComparison != 0 ? typeComparison : a.Name.CompareTo(b.Name);
                    });
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Payload scan was canceled.");
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "An unexpected error occurred while scanning for payloads in {Directory}.", _baseDirectory);
                    throw new PayloadScanException($"An error occurred while scanning for payloads in {_baseDirectory}.", ex);
                }

                return payloads;
            }, cancellationToken);
        }

        /// <summary>
        /// Asynchronously gets the stager payload.
        /// </summary>
        /// <returns>The stager payload as a byte array.</returns>
        public async Task<byte[]> GetStagerPayloadAsync()
        {
            var filePath = await FindPayloadFileAsync(PayloadConstants.STAGER_NAMES);
            return await File.ReadAllBytesAsync(filePath);
        }

        /// <summary>
        /// Asynchronously gets the memory dumper payload.
        /// </summary>
        /// <returns>The memory dumper payload as a byte array.</returns>
        public async Task<byte[]> GetMemoryDumperPayloadAsync()
        {
            var filePath = await FindPayloadFileAsync(PayloadConstants.DUMP_MEM_NAMES);
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
                return PayloadConstants.TYPE_STAGER;
            if (fileName.Contains("dump_mem") || directory.Contains("dump_mem"))
                return PayloadConstants.TYPE_DUMP_MEM;
            if (fileName.Contains("hello") || directory.Contains("hello"))
                return PayloadConstants.TYPE_HELLO;
            if (fileName.Contains("tic_tac_toe") || directory.Contains("tic_tac_toe"))
                return PayloadConstants.TYPE_TIC_TAC_TOE;
            if (fileName.EndsWith(".bin"))
                return PayloadConstants.TYPE_BINARY;

            return PayloadConstants.TYPE_UNKNOWN;
        }

        /// <summary>
        /// Asynchronously and recursively searches for the payload file in the base directory.
        /// </summary>
        private Task<string> FindPayloadFileAsync(string[] possibleNames)
        {
            return Task.Run(() =>
            {
                if (!Directory.Exists(_baseDirectory))
                {
                    throw new DirectoryNotFoundException($"Payloads directory not found: {_baseDirectory}. Please check the path configuration.");
                }

                try
                {
                    foreach (var fileName in possibleNames)
                    {
                        var firstFile = Directory.EnumerateFiles(_baseDirectory, fileName, SearchOption.AllDirectories).FirstOrDefault();
                        if (firstFile != null)
                        {
                            return firstFile;
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException)
                {
                    throw new PayloadScanException($"A file system error occurred while searching for payloads in {_baseDirectory}.", ex);
                }

                var allFiles = Directory.EnumerateFiles(_baseDirectory, "*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .ToArray();

                throw new FileNotFoundException($"None of the expected payload files ({string.Join(", ", possibleNames)}) found under {_baseDirectory}. Available files: {string.Join(", ", allFiles)}");
            });
        }
    }
}