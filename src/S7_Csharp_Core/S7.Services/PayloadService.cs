using System;
using System.Collections.Generic;
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
    /// Service implementation for payload management operations with scanning, loading, validation, and caching capabilities.
    /// </summary>
    public class PayloadService(
        ILogger<PayloadService> logger) : IPayloadService
    {
        private readonly ILogger<PayloadService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly Dictionary<string, LoadedPayload> _payloadCache = new();
        private readonly object _cacheLock = new();

        /// <inheritdoc />
        public async Task<Result<PayloadScanResult>> ScanPayloadsAsync(
            IEnumerable<string> scanPaths,
            PayloadScanOptions? scanOptions = null,
            IProgress<PayloadScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(scanPaths);
            
            var options = scanOptions ?? new PayloadScanOptions();
            var pathList = scanPaths.ToList();
            
            _logger.LogInformation("Starting payload scan in {PathCount} directories", pathList.Count);
            
            try
            {
                var startTime = DateTime.UtcNow;
                var discoveredPayloads = new List<DiscoveredPayload>();
                var directoriesScanned = 0;
                var filesScanned = 0;
                
                foreach (var scanPath in pathList)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    if (!Directory.Exists(scanPath))
                    {
                        _logger.LogWarning("Scan path does not exist: {Path}", scanPath);
                        continue;
                    }
                    
                    var searchOption = options.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                    var files = Directory.GetFiles(scanPath, "*.*", searchOption)
                        .Where(f => options.FileExtensions.Any(ext => f.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                        .ToList();
                    
                    directoriesScanned++;
                    
                    foreach (var file in files)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            var payload = await AnalyzePayloadFile(file, options, cancellationToken);
                            
                            if (payload != null)
                            {
                                discoveredPayloads.Add(payload);
                            }
                            
                            filesScanned++;
                            
                            var progressInfo = new PayloadScanProgress(
                                DirectoriesScanned: directoriesScanned,
                                TotalDirectories: pathList.Count,
                                FilesScanned: filesScanned,
                                CurrentDirectory: Path.GetDirectoryName(file) ?? "",
                                PercentComplete: (double)directoriesScanned / pathList.Count * 100);
                            
                            progress?.Report(progressInfo);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Error analyzing payload file: {File}", file);
                        }
                    }
                }
                
                var scanDuration = DateTime.UtcNow - startTime;
                var scanStatistics = new Dictionary<string, object>
                {
                    ["TotalPayloads"] = discoveredPayloads.Count,
                    ["PayloadTypes"] = discoveredPayloads.GroupBy(p => p.Type).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                    ["AverageFileSize"] = discoveredPayloads.Count > 0 ? discoveredPayloads.Average(p => p.Size) : 0
                };
                
                var result = new PayloadScanResult(
                    DiscoveredPayloads: discoveredPayloads,
                    DirectoriesScanned: directoriesScanned,
                    FilesScanned: filesScanned,
                    ScanDuration: scanDuration,
                    ScanStatistics: scanStatistics);
                
                _logger.LogInformation("Payload scan completed. Found {PayloadCount} payloads in {Duration}ms", 
                    discoveredPayloads.Count, scanDuration.TotalMilliseconds);
                
                return Result<PayloadScanResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during payload scan");
                return Result<PayloadScanResult>.Failure($"Payload scan failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<LoadedPayload>> LoadPayloadAsync(
            string payloadPath,
            PayloadLoadOptions? loadOptions = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            var options = loadOptions ?? new PayloadLoadOptions();
            
            _logger.LogInformation("Loading payload from {Path}", payloadPath);
            
            try
            {
                if (!File.Exists(payloadPath))
                    return Result<LoadedPayload>.Failure($"Payload file not found: {payloadPath}");
                
                var data = await File.ReadAllBytesAsync(payloadPath, cancellationToken);
                var fileInfo = new FileInfo(payloadPath);
                var checksum = ComputeChecksum(data);
                
                var metadata = await ExtractPayloadMetadata(payloadPath, data, cancellationToken);
                
                var loadedPayload = new LoadedPayload(
                    Data: data,
                    Metadata: metadata,
                    FilePath: payloadPath,
                    FileSize: fileInfo.Length,
                    LoadTime: DateTime.UtcNow,
                    Checksum: checksum);
                
                if (options.CachePayload)
                {
                    lock (_cacheLock)
                    {
                        _payloadCache[payloadPath] = loadedPayload;
                    }
                }
                
                _logger.LogInformation("Payload loaded successfully from {Path} ({Size} bytes)", payloadPath, data.Length);
                return Result<LoadedPayload>.Success(loadedPayload);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading payload from {Path}", payloadPath);
                return Result<LoadedPayload>.Failure($"Failed to load payload: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadValidationResult>> ValidatePayloadAsync(
            string payloadPath,
            PayloadValidationOptions? validationOptions = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            var options = validationOptions ?? new PayloadValidationOptions();
            
            _logger.LogInformation("Validating payload: {Path}", payloadPath);
            
            try
            {
                if (!File.Exists(payloadPath))
                    return Result<PayloadValidationResult>.Failure($"Payload file not found: {payloadPath}");
                
                var validationErrors = new List<string>();
                var validationWarnings = new List<string>();
                var validationMetrics = new Dictionary<string, object>();
                
                var fileInfo = new FileInfo(payloadPath);
                validationMetrics["FileSize"] = fileInfo.Length;
                
                // Basic file validation
                if (fileInfo.Length == 0)
                    validationErrors.Add("Payload file is empty");
                
                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB
                    validationWarnings.Add("Payload file is unusually large");
                
                // Format validation
                if (options.CheckFormat)
                {
                    var formatValid = await ValidatePayloadFormat(payloadPath, cancellationToken);
                    if (!formatValid)
                        validationErrors.Add("Invalid payload format");
                }
                
                var securityInfo = new PayloadSecurityInfo(
                    IsSigned: false,
                    IsEncrypted: false,
                    SecurityFlags: new List<string>(),
                    SignatureInfo: null,
                    RiskLevel: SecurityRiskLevel.Medium);
                
                var result = new PayloadValidationResult(
                    IsValid: validationErrors.Count == 0,
                    ValidationErrors: validationErrors,
                    ValidationWarnings: validationWarnings,
                    SecurityInfo: securityInfo,
                    ValidationMetrics: validationMetrics);
                
                return Result<PayloadValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating payload: {Path}", payloadPath);
                return Result<PayloadValidationResult>.Failure($"Validation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadAnalysisResult>> AnalyzePayloadAsync(
            string payloadPath,
            PayloadAnalysisOptions? analysisOptions = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            var options = analysisOptions ?? new PayloadAnalysisOptions();
            
            _logger.LogInformation("Analyzing payload: {Path}", payloadPath);
            
            try
            {
                if (!File.Exists(payloadPath))
                    return Result<PayloadAnalysisResult>.Failure($"Payload file not found: {payloadPath}");
                
                var data = await File.ReadAllBytesAsync(payloadPath, cancellationToken);
                var metadata = await ExtractPayloadMetadata(payloadPath, data, cancellationToken);
                
                var dependencies = new List<string>();
                var compatibility = new CompatibilityInfo(
                    SupportedDevices: new List<string> { "S7-1200", "S7-1500" },
                    RequiredFeatures: new List<string>(),
                    MinimumFirmwareVersion: "4.0",
                    Constraints: new Dictionary<string, object>());
                
                var performance = new PerformanceCharacteristics(
                    MemoryRequirement: (uint)data.Length,
                    ExecutionTime: 1000, // 1 second estimate
                    CpuUsage: 10, // 10% estimate
                    Benchmarks: new Dictionary<string, object>());
                
                var analysisData = new Dictionary<string, object>
                {
                    ["FileSize"] = data.Length,
                    ["Entropy"] = CalculateEntropy(data),
                    ["Checksum"] = ComputeChecksum(data)
                };
                
                var result = new PayloadAnalysisResult(
                    Metadata: metadata,
                    Dependencies: dependencies,
                    Compatibility: compatibility,
                    Performance: performance,
                    AnalysisData: analysisData);
                
                return Result<PayloadAnalysisResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing payload: {Path}", payloadPath);
                return Result<PayloadAnalysisResult>.Failure($"Analysis failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadCreationResult>> CreatePayloadAsync(
            PayloadCreationOptions creationOptions,
            IProgress<PayloadCreationProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(creationOptions);
            
            _logger.LogInformation("Creating payload: {OutputPath}", creationOptions.OutputPath);
            
            try
            {
                // For now, return not implemented
                return Result<PayloadCreationResult>.Failure("Payload creation functionality not yet implemented");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating payload");
                return Result<PayloadCreationResult>.Failure($"Creation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadCompilationResult>> CompilePayloadAsync(
            IEnumerable<string> sourceFiles,
            PayloadCompilationOptions compilationOptions,
            IProgress<PayloadCompilationProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(sourceFiles);
            ArgumentNullException.ThrowIfNull(compilationOptions);
            
            _logger.LogInformation("Compiling payload to: {OutputPath}", compilationOptions.OutputPath);
            
            try
            {
                // For now, return not implemented
                return Result<PayloadCompilationResult>.Failure("Payload compilation functionality not yet implemented");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling payload");
                return Result<PayloadCompilationResult>.Failure($"Compilation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadOptimizationResult>> OptimizePayloadAsync(
            string payloadPath,
            PayloadOptimizationOptions optimizationOptions,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            ArgumentNullException.ThrowIfNull(optimizationOptions);
            
            _logger.LogInformation("Optimizing payload: {Path}", payloadPath);
            
            try
            {
                // For now, return not implemented
                return Result<PayloadOptimizationResult>.Failure("Payload optimization functionality not yet implemented");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error optimizing payload");
                return Result<PayloadOptimizationResult>.Failure($"Optimization failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PayloadCacheResult>> CachePayloadAsync(
            string payloadPath,
            PayloadCacheOptions? cacheOptions = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            var options = cacheOptions ?? new PayloadCacheOptions();
            
            try
            {
                var loadResult = await LoadPayloadAsync(payloadPath, new PayloadLoadOptions { CachePayload = true }, cancellationToken);
                if (!loadResult.IsSuccess)
                    return Result<PayloadCacheResult>.Failure(loadResult.Error.Message);
                
                var cacheKey = ComputeChecksum(System.Text.Encoding.UTF8.GetBytes(payloadPath));
                var result = new PayloadCacheResult(
                    IsCached: true,
                    CacheKey: cacheKey,
                    CacheSize: loadResult.Value.FileSize,
                    CacheTime: DateTime.UtcNow);
                
                return Result<PayloadCacheResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error caching payload: {Path}", payloadPath);
                return Result<PayloadCacheResult>.Failure($"Caching failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<LoadedPayload>> GetCachedPayloadAsync(
            string payloadPath,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            lock (_cacheLock)
            {
                if (_payloadCache.TryGetValue(payloadPath, out var cachedPayload))
                {
                    _logger.LogDebug("Payload found in cache: {Path}", payloadPath);
                    return Result<LoadedPayload>.Success(cachedPayload);
                }
            }
            
            // Not in cache, load from disk
            return await LoadPayloadAsync(payloadPath, new PayloadLoadOptions { CachePayload = true }, cancellationToken);
        }

        /// <inheritdoc />
        public Result<bool> ClearPayloadCache(string? payloadPath = null)
        {
            try
            {
                lock (_cacheLock)
                {
                    if (payloadPath == null)
                    {
                        var count = _payloadCache.Count;
                        _payloadCache.Clear();
                        _logger.LogInformation("Cleared entire payload cache ({Count} items)", count);
                    }
                    else
                    {
                        var removed = _payloadCache.Remove(payloadPath);
                        _logger.LogInformation("Removed payload from cache: {Path} (Success: {Success})", payloadPath, removed);
                    }
                }
                
                return Result<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing payload cache");
                return Result<bool>.Failure($"Cache clear failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public PayloadCacheInfo GetCacheInfo()
        {
            lock (_cacheLock)
            {
                var totalSize = _payloadCache.Values.Sum(p => p.FileSize);
                return new PayloadCacheInfo(
                    CachedPayloads: _payloadCache.Count,
                    TotalCacheSize: totalSize,
                    MaxCacheSize: 100 * 1024 * 1024, // 100MB
                    CacheHitRatio: 0.0, // Would need to track hits/misses
                    LastCleanup: DateTime.UtcNow);
            }
        }

        /// <inheritdoc />
        public async Task<long> EstimatePayloadMemoryUsageAsync(string payloadPath)
        {
            ArgumentException.ThrowIfNullOrEmpty(payloadPath);
            
            try
            {
                if (!File.Exists(payloadPath))
                    return 0;
                
                var fileInfo = new FileInfo(payloadPath);
                // Estimate: file size + metadata overhead + processing overhead
                return fileInfo.Length + 1024 + (fileInfo.Length / 10);
            }
            catch
            {
                return 0;
            }
        }

        private async Task<DiscoveredPayload?> AnalyzePayloadFile(string filePath, PayloadScanOptions options, CancellationToken cancellationToken)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var payloadType = DeterminePayloadType(filePath);
                
                var metadata = new PayloadMetadata(
                    Name: Path.GetFileNameWithoutExtension(filePath),
                    Version: null,
                    Description: null,
                    Author: null,
                    CreationDate: fileInfo.CreationTimeUtc,
                    Type: payloadType,
                    TargetArchitecture: "ARM",
                    EntryPoint: 0,
                    LoadAddress: 0,
                    CustomProperties: new Dictionary<string, string>());
                
                return new DiscoveredPayload(
                    FilePath: filePath,
                    Name: Path.GetFileNameWithoutExtension(filePath),
                    Type: payloadType,
                    Size: fileInfo.Length,
                    LastModified: fileInfo.LastWriteTimeUtc,
                    Version: null,
                    Description: null,
                    Metadata: metadata);
            }
            catch
            {
                return null;
            }
        }

        private async Task<PayloadMetadata> ExtractPayloadMetadata(string filePath, byte[] data, CancellationToken cancellationToken)
        {
            var fileName = Path.GetFileNameWithoutExtension(filePath);
            var payloadType = DeterminePayloadType(filePath);
            
            return new PayloadMetadata(
                Name: fileName,
                Version: "1.0.0",
                Description: $"Payload extracted from {fileName}",
                Author: "Unknown",
                CreationDate: DateTime.UtcNow,
                Type: payloadType,
                TargetArchitecture: "ARM",
                EntryPoint: 0,
                LoadAddress: 0,
                CustomProperties: new Dictionary<string, string>
                {
                    ["FileSize"] = data.Length.ToString(),
                    ["Checksum"] = ComputeChecksum(data)
                });
        }

        private static PayloadType DeterminePayloadType(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            return extension switch
            {
                ".bin" => PayloadType.Binary,
                ".hex" => PayloadType.Binary,
                ".elf" => PayloadType.Binary,
                ".dump" => PayloadType.MemoryDump,
                ".stage" => PayloadType.Stager,
                _ => PayloadType.Unknown
            };
        }

        private async Task<bool> ValidatePayloadFormat(string payloadPath, CancellationToken cancellationToken)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(payloadPath, cancellationToken);
                // Basic validation - check if file has content and reasonable size
                return data.Length > 0 && data.Length < 50 * 1024 * 1024; // Max 50MB
            }
            catch
            {
                return false;
            }
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            
            var frequencies = new int[256];
            foreach (var b in data)
                frequencies[b]++;
            
            double entropy = 0;
            foreach (var freq in frequencies)
            {
                if (freq > 0)
                {
                    var probability = (double)freq / data.Length;
                    entropy -= probability * Math.Log2(probability);
                }
            }
            
            return entropy;
        }

        private static string ComputeChecksum(byte[] data)
        {
            var hash = System.Security.Cryptography.SHA256.HashData(data);
            return Convert.ToHexString(hash);
        }
    }
}