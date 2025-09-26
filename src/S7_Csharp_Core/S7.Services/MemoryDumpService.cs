using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using S7.Net;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for memory dump operations with progress reporting and cancellation support.
    /// </summary>
    public class MemoryDumpService(
        ILogger<MemoryDumpService> logger,
        PayloadManager payloadManager) : IMemoryDumpService
    {
        private readonly ILogger<MemoryDumpService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly PayloadManager _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));

        /// <inheritdoc />
        public event EventHandler<MemoryDumpProgressEventArgs>? ProgressChanged;

        /// <inheritdoc />
        public event EventHandler<MemoryDumpCompletedEventArgs>? DumpCompleted;

        /// <inheritdoc />
        public async Task<Result<MemoryDumpResult>> DumpMemoryAsync(
            MemoryDumpOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();

            _logger.LogInformation("Starting memory dump operation. Address: 0x{Address:X8}, Length: {Length} bytes, CorrelationId: {CorrelationId}",
                options.StartAddress, options.Length, correlationId);

            try
            {
                // Validate options
                var validationResult = ValidateOptions(options);
                if (!validationResult.IsSuccess)
                {
                    return Result<MemoryDumpResult>.Failure(validationResult.Error);
                }

                // Load dump memory payload
                var dumpMemPayload = await LoadDumpMemoryPayloadAsync(options.PayloadPath, cancellationToken).ConfigureAwait(false);
                if (!dumpMemPayload.IsSuccess)
                {
                    return Result<MemoryDumpResult>.Failure(dumpMemPayload.Error);
                }

                // Create PLC client and perform dump
                using var plcClient = CreatePlcClient(options.ChannelConfig);
                
                // Set up progress reporting
                var progress = new Progress<long>(bytesReceived =>
                {
                    var progressArgs = new MemoryDumpProgressEventArgs(
                        correlationId,
                        options.StartAddress,
                        options.Length,
                        (uint)bytesReceived,
                        (double)bytesReceived / options.Length * 100,
                        stopwatch.Elapsed);

                    ProgressChanged?.Invoke(this, progressArgs);
                });

                // Perform the memory dump
                var dumpedData = await plcClient.DumpMemoryAsync(
                    options.StartAddress,
                    options.Length,
                    dumpMemPayload.Value,
                    progress,
                    cancellationToken).ConfigureAwait(false);

                stopwatch.Stop();

                // Create result
                var result = new MemoryDumpResult
                {
                    CorrelationId = correlationId,
                    StartAddress = options.StartAddress,
                    Length = options.Length,
                    Data = dumpedData,
                    Duration = stopwatch.Elapsed,
                    Timestamp = DateTime.UtcNow,
                    IsSuccess = true,
                    Metadata = new Dictionary<string, object>
                    {
                        ["PayloadPath"] = options.PayloadPath,
                        ["PayloadSize"] = dumpMemPayload.Value.Length,
                        ["ChannelType"] = options.ChannelConfig.Mode,
                        ["DumpSpeed"] = CalculateDumpSpeed(dumpedData.Length, stopwatch.Elapsed)
                    }
                };

                // Save to file if requested
                if (!string.IsNullOrEmpty(options.OutputPath))
                {
                    await SaveDumpToFileAsync(result, options.OutputPath, cancellationToken).ConfigureAwait(false);
                    result.Metadata["OutputPath"] = options.OutputPath;
                }

                _logger.LogInformation("Memory dump completed successfully. Dumped {DataLength} bytes in {Duration}ms. CorrelationId: {CorrelationId}",
                    dumpedData.Length, stopwatch.ElapsedMilliseconds, correlationId);

                // Raise completion event
                var completedArgs = new MemoryDumpCompletedEventArgs(correlationId, result, null);
                DumpCompleted?.Invoke(this, completedArgs);

                return Result<MemoryDumpResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Memory dump operation was cancelled. CorrelationId: {CorrelationId}", correlationId);
                var cancelledArgs = new MemoryDumpCompletedEventArgs(correlationId, null, "Operation was cancelled");
                DumpCompleted?.Invoke(this, cancelledArgs);
                return Result<MemoryDumpResult>.Failure("Memory dump operation was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Memory dump operation failed. CorrelationId: {CorrelationId}", correlationId);
                var errorArgs = new MemoryDumpCompletedEventArgs(correlationId, null, ex.Message);
                DumpCompleted?.Invoke(this, errorArgs);
                return Result<MemoryDumpResult>.Failure($"Memory dump failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<MemoryDumpComparisonResult>> CompareMemoryDumpsAsync(
            MemoryDumpComparisonOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Starting memory dump comparison. CorrelationId: {CorrelationId}", correlationId);

            try
            {
                // Load dump files
                var dump1 = await LoadDumpFromFileAsync(options.FirstDumpPath, cancellationToken).ConfigureAwait(false);
                if (!dump1.IsSuccess)
                {
                    return Result<MemoryDumpComparisonResult>.Failure($"Failed to load first dump: {dump1.Error.Message}");
                }

                var dump2 = await LoadDumpFromFileAsync(options.SecondDumpPath, cancellationToken).ConfigureAwait(false);
                if (!dump2.IsSuccess)
                {
                    return Result<MemoryDumpComparisonResult>.Failure($"Failed to load second dump: {dump2.Error.Message}");
                }

                // Perform comparison
                var differences = CompareDumps(dump1.Value, dump2.Value, options);

                var result = new MemoryDumpComparisonResult
                {
                    CorrelationId = correlationId,
                    FirstDumpPath = options.FirstDumpPath,
                    SecondDumpPath = options.SecondDumpPath,
                    Differences = differences,
                    TotalDifferences = differences.Count,
                    ComparisonTimestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>
                    {
                        ["FirstDumpSize"] = dump1.Value.Length,
                        ["SecondDumpSize"] = dump2.Value.Length,
                        ["ComparisonMode"] = options.ComparisonMode.ToString(),
                        ["IgnoreZeroBytes"] = options.IgnoreZeroBytes
                    }
                };

                _logger.LogInformation("Memory dump comparison completed. Found {DifferenceCount} differences. CorrelationId: {CorrelationId}",
                    differences.Count, correlationId);

                return Result<MemoryDumpComparisonResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Memory dump comparison failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<MemoryDumpComparisonResult>.Failure($"Memory dump comparison failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<MemoryDumpAnalysisResult>> AnalyzeMemoryDumpAsync(
            MemoryDumpAnalysisOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Starting memory dump analysis. CorrelationId: {CorrelationId}", correlationId);

            try
            {
                // Load dump file
                var dumpData = await LoadDumpFromFileAsync(options.DumpPath, cancellationToken).ConfigureAwait(false);
                if (!dumpData.IsSuccess)
                {
                    return Result<MemoryDumpAnalysisResult>.Failure($"Failed to load dump: {dumpData.Error.Message}");
                }

                // Perform analysis
                var analysis = PerformMemoryAnalysis(dumpData.Value, options);

                var result = new MemoryDumpAnalysisResult
                {
                    CorrelationId = correlationId,
                    DumpPath = options.DumpPath,
                    Analysis = analysis,
                    AnalysisTimestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>
                    {
                        ["DumpSize"] = dumpData.Value.Length,
                        ["AnalysisTypes"] = string.Join(", ", options.AnalysisTypes),
                        ["PatternSearchEnabled"] = options.SearchPatterns?.Count > 0
                    }
                };

                _logger.LogInformation("Memory dump analysis completed. CorrelationId: {CorrelationId}", correlationId);
                return Result<MemoryDumpAnalysisResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Memory dump analysis failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<MemoryDumpAnalysisResult>.Failure($"Memory dump analysis failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<ValidationResult>> ValidateMemoryDumpAsync(
            string dumpPath,
            MemoryDumpValidationOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(dumpPath);
            ArgumentNullException.ThrowIfNull(options);

            try
            {
                var errors = new List<string>();

                // Check file existence
                if (!File.Exists(dumpPath))
                {
                    errors.Add($"Dump file does not exist: {dumpPath}");
                    return Result<ValidationResult>.Success(ValidationResult.Failure(errors));
                }

                // Check file size
                var fileInfo = new FileInfo(dumpPath);
                if (fileInfo.Length == 0)
                {
                    errors.Add("Dump file is empty");
                }

                if (options.ExpectedSize.HasValue && fileInfo.Length != options.ExpectedSize.Value)
                {
                    errors.Add($"Dump file size ({fileInfo.Length}) does not match expected size ({options.ExpectedSize.Value})");
                }

                // Load and validate content if needed
                if (options.ValidateContent)
                {
                    var dumpData = await File.ReadAllBytesAsync(dumpPath, cancellationToken).ConfigureAwait(false);
                    
                    // Check for common corruption patterns
                    if (IsAllZeros(dumpData))
                    {
                        errors.Add("Dump appears to be all zeros (possible corruption)");
                    }

                    if (options.ExpectedChecksum != null)
                    {
                        var actualChecksum = CalculateChecksum(dumpData);
                        if (actualChecksum != options.ExpectedChecksum)
                        {
                            errors.Add($"Checksum mismatch. Expected: {options.ExpectedChecksum}, Actual: {actualChecksum}");
                        }
                    }
                }

                var validationResult = errors.Count == 0 
                    ? ValidationResult.Success() 
                    : ValidationResult.Failure(errors);

                return Result<ValidationResult>.Success(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Memory dump validation failed for file: {DumpPath}", dumpPath);
                return Result<ValidationResult>.Failure($"Validation failed: {ex.Message}");
            }
        }

        private Result ValidateOptions(MemoryDumpOptions options)
        {
            var errors = new List<string>();

            if (options.Length == 0)
                errors.Add("Length must be greater than 0");

            if (string.IsNullOrEmpty(options.PayloadPath))
                errors.Add("PayloadPath is required");

            if (options.ChannelConfig == null)
                errors.Add("ChannelConfig is required");

            return errors.Count == 0 
                ? Result.Success() 
                : Result.Failure(string.Join("; ", errors));
        }

        private async Task<Result<byte[]>> LoadDumpMemoryPayloadAsync(string payloadPath, CancellationToken cancellationToken)
        {
            try
            {
                var payload = await _payloadManager.LoadPayloadAsync(payloadPath, cancellationToken).ConfigureAwait(false);
                return payload != null 
                    ? Result<byte[]>.Success(payload) 
                    : Result<byte[]>.Failure("Failed to load payload");
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private PlcClient CreatePlcClient(CommunicationChannelConfig config)
        {
            var channel = config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new S7.Net.Channels.TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new S7.Net.Channels.SerialChannel(config.SerialPort ?? "COM1", config.BaudRate),
                _ => throw new ArgumentException($"Unsupported connection type: {config.Mode}")
            };

            Action<string> logger = message => _logger.LogDebug("{Message}", message);
            return new PlcClient(channel, logger);
        }

        private async Task SaveDumpToFileAsync(MemoryDumpResult result, string outputPath, CancellationToken cancellationToken)
        {
            var directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllBytesAsync(outputPath, result.Data, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Memory dump saved to file: {OutputPath}", outputPath);
        }

        private async Task<Result<byte[]>> LoadDumpFromFileAsync(string filePath, CancellationToken cancellationToken)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return Result<byte[]>.Failure($"File does not exist: {filePath}");
                }

                var data = await File.ReadAllBytesAsync(filePath, cancellationToken).ConfigureAwait(false);
                return Result<byte[]>.Success(data);
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private List<MemoryDifference> CompareDumps(byte[] dump1, byte[] dump2, MemoryDumpComparisonOptions options)
        {
            var differences = new List<MemoryDifference>();
            var maxLength = Math.Max(dump1.Length, dump2.Length);

            for (int i = 0; i < maxLength; i++)
            {
                byte byte1 = i < dump1.Length ? dump1[i] : (byte)0;
                byte byte2 = i < dump2.Length ? dump2[i] : (byte)0;

                if (byte1 != byte2)
                {
                    if (options.IgnoreZeroBytes && (byte1 == 0 || byte2 == 0))
                        continue;

                    differences.Add(new MemoryDifference
                    {
                        Offset = (uint)i,
                        FirstValue = byte1,
                        SecondValue = byte2,
                        DifferenceType = DetermineDifferenceType(byte1, byte2)
                    });
                }
            }

            return differences;
        }

        private Dictionary<string, object> PerformMemoryAnalysis(byte[] dumpData, MemoryDumpAnalysisOptions options)
        {
            var analysis = new Dictionary<string, object>();

            // Basic statistics
            analysis["Size"] = dumpData.Length;
            analysis["ZeroBytes"] = CountZeroBytes(dumpData);
            analysis["NonZeroBytes"] = dumpData.Length - (int)analysis["ZeroBytes"];
            analysis["Entropy"] = CalculateEntropy(dumpData);

            // Pattern search if requested
            if (options.SearchPatterns?.Count > 0)
            {
                var patternMatches = new Dictionary<string, List<uint>>();
                foreach (var pattern in options.SearchPatterns)
                {
                    var matches = FindPatternMatches(dumpData, pattern.Value);
                    patternMatches[pattern.Key] = matches;
                }
                analysis["PatternMatches"] = patternMatches;
            }

            // String analysis if requested
            if (options.AnalysisTypes.Contains("strings"))
            {
                analysis["Strings"] = ExtractStrings(dumpData);
            }

            return analysis;
        }

        private double CalculateDumpSpeed(int dataLength, TimeSpan duration)
        {
            return duration.TotalSeconds > 0 ? dataLength / duration.TotalSeconds : 0;
        }

        private MemoryDifferenceType DetermineDifferenceType(byte byte1, byte byte2)
        {
            if (byte1 == 0) return MemoryDifferenceType.AddedByte;
            if (byte2 == 0) return MemoryDifferenceType.RemovedByte;
            return MemoryDifferenceType.ModifiedByte;
        }

        private int CountZeroBytes(byte[] data)
        {
            int count = 0;
            foreach (byte b in data)
            {
                if (b == 0) count++;
            }
            return count;
        }

        private double CalculateEntropy(byte[] data)
        {
            var frequencies = new int[256];
            foreach (byte b in data)
            {
                frequencies[b]++;
            }

            double entropy = 0;
            int length = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double probability = (double)frequencies[i] / length;
                    entropy -= probability * Math.Log2(probability);
                }
            }

            return entropy;
        }

        private List<uint> FindPatternMatches(byte[] data, byte[] pattern)
        {
            var matches = new List<uint>();
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    matches.Add((uint)i);
                }
            }
            return matches;
        }

        private List<string> ExtractStrings(byte[] data)
        {
            var strings = new List<string>();
            var currentString = new List<byte>();

            foreach (byte b in data)
            {
                if (b >= 32 && b <= 126) // Printable ASCII
                {
                    currentString.Add(b);
                }
                else
                {
                    if (currentString.Count >= 4) // Minimum string length
                    {
                        strings.Add(System.Text.Encoding.ASCII.GetString(currentString.ToArray()));
                    }
                    currentString.Clear();
                }
            }

            if (currentString.Count >= 4)
            {
                strings.Add(System.Text.Encoding.ASCII.GetString(currentString.ToArray()));
            }

            return strings;
        }

        private bool IsAllZeros(byte[] data)
        {
            foreach (byte b in data)
            {
                if (b != 0) return false;
            }
            return true;
        }

        private string CalculateChecksum(byte[] data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(data);
            return Convert.ToHexString(hash);
        }
    }
}