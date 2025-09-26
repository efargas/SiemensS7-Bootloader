using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for payload operations with async scanning and caching capabilities.
    /// </summary>
    public class PayloadService(
        ILogger<PayloadService> logger) : IPayloadService
    {
        private readonly ILogger<PayloadService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly ConcurrentDictionary<string, PayloadCacheEntry> _payloadCache = new();
        private readonly ConcurrentDictionary<string, PayloadScanResult> _scanCache = new();
        private readonly SemaphoreSlim _scanSemaphore = new(1, 1);

        /// <inheritdoc />
        public event EventHandler<PayloadScanProgressEventArgs>? ScanProgressChanged;

        /// <inheritdoc />
        public event EventHandler<PayloadScanCompletedEventArgs>? ScanCompleted;

        /// <inheritdoc />
        public event EventHandler<PayloadLoadedEventArgs>? PayloadLoaded;

        /// <inheritdoc />
        public async Task<Result<PayloadScanResult>> ScanPayloadsAsync(
            PayloadScanOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();

            _logger.LogInformation("Starting payload scan. Directory: {Directory}, CorrelationId: {CorrelationId}",
                options.ScanDirectory, correlationId);

            await _scanSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Check cache first if enabled
                if (options.UseCache && _scanCache.TryGetValue(options.ScanDirectory, out var cachedResult))
                {
                    var cacheAge = DateTime.UtcNow - cachedResult.ScanTimestamp;
                    if (cacheAge < options.CacheExpiry)
                    {
                        _logger.LogInformation("Returning cached scan result. Age: {CacheAge}. CorrelationId: {CorrelationId}",
                            cacheAge, correlationId);
                        return Result<PayloadScanResult>.Success(cachedResult);
                    }
                }

                // Validate scan directory
                if (!Directory.Exists(options.ScanDirectory))
                {
                    return Result<PayloadScanResult>.Failure($"Scan directory does not exist: {options.ScanDirectory}");
                }

                var payloads = new List<PayloadInfo>();
                var errors = new List<string>();

                // Get all files matching patterns
                var allFiles = GetFilesMatchingPatterns(options.ScanDirectory, options.FilePatterns, options.Recursive);
                var totalFiles = allFiles.Count;

                _logger.LogInformation("Found {FileCount} files to scan. CorrelationId: {CorrelationId}",
                    totalFiles, correlationId);

                // Scan files
                for (int i = 0; i < allFiles.Count; i++)
                {
                    var filePath = allFiles[i];
                    
                    try
                    {
                        // Report progress
                        var progressArgs = new PayloadScanProgressEventArgs(
                            correlationId,
                            filePath,
                            i + 1,
                            totalFiles,
                            (double)(i + 1) / totalFiles * 100);
                        ScanProgressChanged?.Invoke(this, progressArgs);

                        // Scan individual file
                        var payloadInfo = await ScanPayloadFileAsync(filePath, options, cancellationToken).ConfigureAwait(false);
                        if (payloadInfo.IsSuccess)
                        {
                            payloads.Add(payloadInfo.Value);
                        }
                        else
                        {
                            errors.Add($"{filePath}: {payloadInfo.Error.Message}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to scan payload file: {FilePath}. CorrelationId: {CorrelationId}",
                            filePath, correlationId);
                        errors.Add($"{filePath}: {ex.Message}");
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                }

                stopwatch.Stop();

                var result = new PayloadScanResult
                {
                    CorrelationId = correlationId,
                    ScanDirectory = options.ScanDirectory,
                    Payloads = payloads,
                    TotalFiles = totalFiles,
                    SuccessfulScans = payloads.Count,
                    FailedScans = errors.Count,
                    ScanDuration = stopwatch.Elapsed,
                    ScanTimestamp = DateTime.UtcNow,
                    Errors = errors,
                    Metadata = new Dictionary<string, object>
                    {
                        ["ScanSpeed"] = CalculateScanSpeed(totalFiles, stopwatch.Elapsed),
                        ["FilePatterns"] = string.Join(", ", options.FilePatterns),
                        ["Recursive"] = options.Recursive,
                        ["CacheUsed"] = options.UseCache
                    }
                };

                // Cache result if enabled
                if (options.UseCache)
                {
                    _scanCache.AddOrUpdate(options.ScanDirectory, result, (key, oldValue) => result);
                }

                _logger.LogInformation("Payload scan completed. Found {PayloadCount} payloads in {Duration}ms. CorrelationId: {CorrelationId}",
                    payloads.Count, stopwatch.ElapsedMilliseconds, correlationId);

                // Raise completion event
                var completedArgs = new PayloadScanCompletedEventArgs(correlationId, result, null);
                ScanCompleted?.Invoke(this, completedArgs);

                return Result<PayloadScanResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Payload scan was cancelled. CorrelationId: {CorrelationId}", correlationId);
                var cancelledArgs = new PayloadScanCompletedEventArgs(correlationId, null, "Scan was cancelled");
                ScanCompleted?.Invoke(this, cancelledArgs);
                return Result<PayloadScanResult>.Failure("Payload scan was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Payload scan failed. CorrelationId: {CorrelationId}", correlationId);
                var errorArgs = new PayloadScanCompletedEventArgs(correlationId, null, ex.Message);
                ScanCompleted?.Invoke(this, errorArgs);
                return Result<PayloadScanResult>.Failure($"Payload scan failed: {ex.Message}");
            }
            finally
            {
                _scanSemaphore.Release();
            }
        }

        /// <inheritdoc />
        public async Task<Result<byte[]>> LoadPayloadAsync(
            string payloadPath,
            PayloadLoadOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            options ??= new PayloadLoadOptions();

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Loading payload. Path: {PayloadPath}, CorrelationId: {CorrelationId}",
                payloadPath, correlationId);

            try
            {
                // Check cache first if enabled
                if (options.UseCache && _payloadCache.TryGetValue(payloadPath, out var cachedEntry))
                {
                    var cacheAge = DateTime.UtcNow - cachedEntry.LoadTimestamp;
                    if (cacheAge < options.CacheExpiry)
                    {
                        _logger.LogInformation("Returning cached payload. Size: {Size} bytes, Age: {CacheAge}. CorrelationId: {CorrelationId}",
                            cachedEntry.Data.Length, cacheAge, correlationId);
                        return Result<byte[]>.Success(cachedEntry.Data);
                    }
                }

                // Validate file
                if (!File.Exists(payloadPath))
                {
                    return Result<byte[]>.Failure($"Payload file does not exist: {payloadPath}");
                }

                var fileInfo = new FileInfo(payloadPath);
                if (fileInfo.Length == 0)
                {
                    return Result<byte[]>.Failure("Payload file is empty");
                }

                if (options.MaxFileSize.HasValue && fileInfo.Length > options.MaxFileSize.Value)
                {
                    return Result<byte[]>.Failure($"Payload file size ({fileInfo.Length}) exceeds maximum allowed size ({options.MaxFileSize.Value})");
                }

                // Load file
                var data = await File.ReadAllBytesAsync(payloadPath, cancellationToken).ConfigureAwait(false);

                // Validate content if requested
                if (options.ValidateContent)
                {
                    var validationResult = ValidatePayloadContent(data, options);
                    if (!validationResult.IsSuccess)
                    {
                        return Result<byte[]>.Failure(validationResult.Error.Message);
                    }
                }

                // Cache if enabled
                if (options.UseCache)
                {
                    var cacheEntry = new PayloadCacheEntry
                    {
                        Data = data,
                        LoadTimestamp = DateTime.UtcNow,
                        FilePath = payloadPath,
                        FileSize = data.Length
                    };
                    _payloadCache.AddOrUpdate(payloadPath, cacheEntry, (key, oldValue) => cacheEntry);
                }

                _logger.LogInformation("Payload loaded successfully. Size: {Size} bytes. CorrelationId: {CorrelationId}",
                    data.Length, correlationId);

                // Raise loaded event
                var loadedArgs = new PayloadLoadedEventArgs(correlationId, payloadPath, data.Length);
                PayloadLoaded?.Invoke(this, loadedArgs);

                return Result<byte[]>.Success(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load payload: {PayloadPath}. CorrelationId: {CorrelationId}",
                    payloadPath, correlationId);
                return Result<byte[]>.Failure($"Failed to load payload: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadValidationResult>> ValidatePayloadAsync(
            string payloadPath,
            PayloadValidationOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Validating payload. Path: {PayloadPath}, CorrelationId: {CorrelationId}",
                payloadPath, correlationId);

            try
            {
                var validationSteps = new List<PayloadValidationStep>();

                // Step 1: File existence and basic checks
                var fileCheckResult = ValidateFileBasics(payloadPath, options);
                validationSteps.Add(new PayloadValidationStep
                {
                    StepName = "File Basic Checks",
                    IsSuccess = fileCheckResult.IsSuccess,
                    ErrorMessage = fileCheckResult.IsSuccess ? null : fileCheckResult.Error.Message
                });

                if (!fileCheckResult.IsSuccess)
                {
                    return CreateValidationResult(correlationId, payloadPath, validationSteps, options);
                }

                // Step 2: Load and validate content
                var loadResult = await LoadPayloadAsync(payloadPath, new PayloadLoadOptions
                {
                    UseCache = false,
                    ValidateContent = false,
                    CorrelationId = correlationId
                }, cancellationToken).ConfigureAwait(false);

                validationSteps.Add(new PayloadValidationStep
                {
                    StepName = "Content Loading",
                    IsSuccess = loadResult.IsSuccess,
                    ErrorMessage = loadResult.IsSuccess ? null : loadResult.Error.Message
                });

                if (!loadResult.IsSuccess)
                {
                    return CreateValidationResult(correlationId, payloadPath, validationSteps, options);
                }

                // Step 3: Content validation
                var contentValidationResult = ValidatePayloadContent(loadResult.Value, options);
                validationSteps.Add(new PayloadValidationStep
                {
                    StepName = "Content Validation",
                    IsSuccess = contentValidationResult.IsSuccess,
                    ErrorMessage = contentValidationResult.IsSuccess ? null : contentValidationResult.Error.Message
                });

                // Step 4: Architecture validation (if specified)
                if (!string.IsNullOrEmpty(options.ExpectedArchitecture))
                {
                    var archValidationResult = ValidatePayloadArchitecture(loadResult.Value, options);
                    validationSteps.Add(new PayloadValidationStep
                    {
                        StepName = "Architecture Validation",
                        IsSuccess = archValidationResult.IsSuccess,
                        ErrorMessage = archValidationResult.IsSuccess ? null : archValidationResult.Error.Message
                    });
                }

                return CreateValidationResult(correlationId, payloadPath, validationSteps, options);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Payload validation failed: {PayloadPath}. CorrelationId: {CorrelationId}",
                    payloadPath, correlationId);
                return Result<PayloadValidationResult>.Failure($"Payload validation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadCompilationResult>> CompilePayloadAsync(
            PayloadCompilationOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Compiling payload. Source: {SourcePath}, CorrelationId: {CorrelationId}",
                options.SourcePath, correlationId);

            try
            {
                // Validate source files exist
                if (!File.Exists(options.SourcePath))
                {
                    return Result<PayloadCompilationResult>.Failure($"Source file does not exist: {options.SourcePath}");
                }

                // Simulate compilation process
                var compilationSteps = new List<PayloadCompilationStep>();

                // Step 1: Preprocessing
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                compilationSteps.Add(new PayloadCompilationStep
                {
                    StepName = "Preprocessing",
                    IsSuccess = true,
                    Duration = TimeSpan.FromMilliseconds(100)
                });

                // Step 2: Compilation
                await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                compilationSteps.Add(new PayloadCompilationStep
                {
                    StepName = "Compilation",
                    IsSuccess = true,
                    Duration = TimeSpan.FromMilliseconds(500)
                });

                // Step 3: Linking
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                compilationSteps.Add(new PayloadCompilationStep
                {
                    StepName = "Linking",
                    IsSuccess = true,
                    Duration = TimeSpan.FromMilliseconds(200)
                });

                // Step 4: Post-processing
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                compilationSteps.Add(new PayloadCompilationStep
                {
                    StepName = "Post-processing",
                    IsSuccess = true,
                    Duration = TimeSpan.FromMilliseconds(100)
                });

                var result = new PayloadCompilationResult
                {
                    CorrelationId = correlationId,
                    SourcePath = options.SourcePath,
                    OutputPath = options.OutputPath,
                    IsSuccess = compilationSteps.TrueForAll(s => s.IsSuccess),
                    CompilationSteps = compilationSteps,
                    CompilationTimestamp = DateTime.UtcNow,
                    TotalDuration = compilationSteps.Sum(s => s.Duration.TotalMilliseconds),
                    Metadata = new Dictionary<string, object>
                    {
                        ["CompilerVersion"] = "1.0.0",
                        ["TargetArchitecture"] = options.TargetArchitecture ?? "ARM",
                        ["OptimizationLevel"] = options.OptimizationLevel.ToString()
                    }
                };

                _logger.LogInformation("Payload compilation completed. Success: {IsSuccess}, Duration: {Duration}ms. CorrelationId: {CorrelationId}",
                    result.IsSuccess, result.TotalDuration, correlationId);

                return Result<PayloadCompilationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Payload compilation failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<PayloadCompilationResult>.Failure($"Payload compilation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public void ClearCache()
        {
            var payloadCount = _payloadCache.Count;
            var scanCount = _scanCache.Count;

            _payloadCache.Clear();
            _scanCache.Clear();

            _logger.LogInformation("Cache cleared. Removed {PayloadCount} payload entries and {ScanCount} scan entries",
                payloadCount, scanCount);
        }

        /// <inheritdoc />
        public PayloadCacheStatistics GetCacheStatistics()
        {
            var payloadEntries = _payloadCache.Values.ToList();
            var scanEntries = _scanCache.Values.ToList();

            return new PayloadCacheStatistics
            {
                PayloadCacheEntries = payloadEntries.Count,
                ScanCacheEntries = scanEntries.Count,
                TotalCachedPayloadSize = payloadEntries.Sum(e => e.FileSize),
                OldestPayloadEntry = payloadEntries.Count > 0 ? payloadEntries.Min(e => e.LoadTimestamp) : null,
                NewestPayloadEntry = payloadEntries.Count > 0 ? payloadEntries.Max(e => e.LoadTimestamp) : null,
                OldestScanEntry = scanEntries.Count > 0 ? scanEntries.Min(e => e.ScanTimestamp) : null,
                NewestScanEntry = scanEntries.Count > 0 ? scanEntries.Max(e => e.ScanTimestamp) : null
            };
        }

        private List<string> GetFilesMatchingPatterns(string directory, List<string> patterns, bool recursive)
        {
            var files = new List<string>();
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

            foreach (var pattern in patterns)
            {
                try
                {
                    var matchingFiles = Directory.GetFiles(directory, pattern, searchOption);
                    files.AddRange(matchingFiles);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to search for files with pattern: {Pattern}", pattern);
                }
            }

            return files.Distinct().ToList();
        }

        private async Task<Result<PayloadInfo>> ScanPayloadFileAsync(
            string filePath,
            PayloadScanOptions options,
            CancellationToken cancellationToken)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                
                // Basic file validation
                if (fileInfo.Length == 0)
                {
                    return Result<PayloadInfo>.Failure("File is empty");
                }

                // Load file for analysis if requested
                byte[]? fileData = null;
                if (options.AnalyzeContent)
                {
                    fileData = await File.ReadAllBytesAsync(filePath, cancellationToken).ConfigureAwait(false);
                }

                var payloadInfo = new PayloadInfo
                {
                    FilePath = filePath,
                    FileName = fileInfo.Name,
                    FileSize = fileInfo.Length,
                    LastModified = fileInfo.LastWriteTime,
                    PayloadType = DeterminePayloadType(filePath, fileData),
                    Architecture = DetermineArchitecture(filePath, fileData),
                    IsValid = true,
                    Metadata = new Dictionary<string, object>
                    {
                        ["Extension"] = fileInfo.Extension,
                        ["Directory"] = fileInfo.DirectoryName ?? "",
                        ["CreationTime"] = fileInfo.CreationTime
                    }
                };

                if (fileData != null)
                {
                    payloadInfo.Metadata["Checksum"] = CalculateChecksum(fileData);
                    payloadInfo.Metadata["Entropy"] = CalculateEntropy(fileData);
                }

                return Result<PayloadInfo>.Success(payloadInfo);
            }
            catch (Exception ex)
            {
                return Result<PayloadInfo>.Failure(ex);
            }
        }

        private Result ValidateFileBasics(string filePath, PayloadValidationOptions options)
        {
            var errors = new List<string>();

            if (!File.Exists(filePath))
            {
                errors.Add("File does not exist");
            }
            else
            {
                var fileInfo = new FileInfo(filePath);
                
                if (fileInfo.Length == 0)
                {
                    errors.Add("File is empty");
                }

                if (options.MaxFileSize.HasValue && fileInfo.Length > options.MaxFileSize.Value)
                {
                    errors.Add($"File size ({fileInfo.Length}) exceeds maximum allowed size ({options.MaxFileSize.Value})");
                }

                if (options.AllowedExtensions?.Count > 0)
                {
                    var extension = fileInfo.Extension.ToLowerInvariant();
                    if (!options.AllowedExtensions.Contains(extension))
                    {
                        errors.Add($"File extension '{extension}' is not allowed");
                    }
                }
            }

            return errors.Count == 0 
                ? Result.Success() 
                : Result.Failure(string.Join("; ", errors));
        }

        private Result ValidatePayloadContent(byte[] data, PayloadValidationOptions options)
        {
            var errors = new List<string>();

            // Check for minimum size
            if (options.MinFileSize.HasValue && data.Length < options.MinFileSize.Value)
            {
                errors.Add($"Content size ({data.Length}) is below minimum required size ({options.MinFileSize.Value})");
            }

            // Check for expected magic bytes
            if (options.ExpectedMagicBytes?.Length > 0)
            {
                if (data.Length < options.ExpectedMagicBytes.Length)
                {
                    errors.Add("Content is too short to contain expected magic bytes");
                }
                else
                {
                    for (int i = 0; i < options.ExpectedMagicBytes.Length; i++)
                    {
                        if (data[i] != options.ExpectedMagicBytes[i])
                        {
                            errors.Add("Content does not start with expected magic bytes");
                            break;
                        }
                    }
                }
            }

            // Check checksum if provided
            if (!string.IsNullOrEmpty(options.ExpectedChecksum))
            {
                var actualChecksum = CalculateChecksum(data);
                if (actualChecksum != options.ExpectedChecksum)
                {
                    errors.Add($"Checksum mismatch. Expected: {options.ExpectedChecksum}, Actual: {actualChecksum}");
                }
            }

            return errors.Count == 0 
                ? Result.Success() 
                : Result.Failure(string.Join("; ", errors));
        }

        private Result ValidatePayloadContent(byte[] data, PayloadLoadOptions options)
        {
            // Basic content validation for load options
            if (data.Length == 0)
            {
                return Result.Failure("Payload content is empty");
            }

            return Result.Success();
        }

        private Result ValidatePayloadArchitecture(byte[] data, PayloadValidationOptions options)
        {
            // Simulate architecture validation
            var detectedArch = DetermineArchitecture("", data);
            
            if (!string.IsNullOrEmpty(options.ExpectedArchitecture) && 
                !string.Equals(detectedArch, options.ExpectedArchitecture, StringComparison.OrdinalIgnoreCase))
            {
                return Result.Failure($"Architecture mismatch. Expected: {options.ExpectedArchitecture}, Detected: {detectedArch}");
            }

            return Result.Success();
        }

        private Result<PayloadValidationResult> CreateValidationResult(
            string correlationId,
            string payloadPath,
            List<PayloadValidationStep> validationSteps,
            PayloadValidationOptions options)
        {
            var overallSuccess = validationSteps.TrueForAll(s => s.IsSuccess);

            var result = new PayloadValidationResult
            {
                CorrelationId = correlationId,
                PayloadPath = payloadPath,
                IsValid = overallSuccess,
                ValidationSteps = validationSteps,
                ValidationTimestamp = DateTime.UtcNow,
                TotalSteps = validationSteps.Count,
                PassedSteps = validationSteps.Count(s => s.IsSuccess),
                Metadata = new Dictionary<string, object>
                {
                    ["ValidationMode"] = options.ValidationMode.ToString(),
                    ["ExpectedArchitecture"] = options.ExpectedArchitecture ?? "Not specified",
                    ["ChecksumValidation"] = !string.IsNullOrEmpty(options.ExpectedChecksum)
                }
            };

            return Result<PayloadValidationResult>.Success(result);
        }

        private string DeterminePayloadType(string filePath, byte[]? data)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            
            return extension switch
            {
                ".bin" => "Binary",
                ".elf" => "ELF Executable",
                ".hex" => "Intel HEX",
                ".s" => "Assembly Source",
                ".c" => "C Source",
                _ => "Unknown"
            };
        }

        private string DetermineArchitecture(string filePath, byte[]? data)
        {
            // Simple heuristic based on file content or name
            if (data != null && data.Length >= 4)
            {
                // Check for ELF magic
                if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46)
                {
                    return "ELF";
                }
            }

            // Default assumption for this project
            return "ARM";
        }

        private string CalculateChecksum(byte[] data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(data);
            return Convert.ToHexString(hash);
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

        private double CalculateScanSpeed(int fileCount, TimeSpan duration)
        {
            return duration.TotalSeconds > 0 ? fileCount / duration.TotalSeconds : 0;
        }

        /// <summary>
        /// Represents a cached payload entry.
        /// </summary>
        private class PayloadCacheEntry
        {
            public byte[] Data { get; set; } = Array.Empty<byte>();
            public DateTime LoadTimestamp { get; set; }
            public string FilePath { get; set; } = string.Empty;
            public long FileSize { get; set; }
        }
    }
}