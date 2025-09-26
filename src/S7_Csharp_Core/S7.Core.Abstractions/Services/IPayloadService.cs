using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Service interface for payload management operations providing comprehensive payload discovery, loading, and validation capabilities.
    /// </summary>
    public interface IPayloadService
    {
        /// <summary>
        /// Scans the specified directories for available payloads asynchronously with caching support.
        /// </summary>
        /// <param name="scanPaths">The directories to scan for payloads</param>
        /// <param name="scanOptions">Options controlling the scan process</param>
        /// <param name="progress">Optional progress reporter for tracking scan progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload scan operation result</returns>
        Task<Result<PayloadScanResult>> ScanPayloadsAsync(
            IEnumerable<string> scanPaths,
            PayloadScanOptions? scanOptions = null,
            IProgress<PayloadScanProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Loads a payload from the specified path with validation and metadata extraction.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file</param>
        /// <param name="loadOptions">Options controlling the load process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload load operation result</returns>
        Task<Result<LoadedPayload>> LoadPayloadAsync(
            string payloadPath,
            PayloadLoadOptions? loadOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates a payload file for integrity, format compliance, and security requirements.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file to validate</param>
        /// <param name="validationOptions">Options controlling the validation process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload validation result</returns>
        Task<Result<PayloadValidationResult>> ValidatePayloadAsync(
            string payloadPath,
            PayloadValidationOptions? validationOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Analyzes a payload to extract metadata, dependencies, and compatibility information.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file to analyze</param>
        /// <param name="analysisOptions">Options controlling the analysis process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload analysis result</returns>
        Task<Result<PayloadAnalysisResult>> AnalyzePayloadAsync(
            string payloadPath,
            PayloadAnalysisOptions? analysisOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new payload from source code or binary data with specified configuration.
        /// </summary>
        /// <param name="creationOptions">The payload creation configuration</param>
        /// <param name="progress">Optional progress reporter for tracking creation progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload creation result</returns>
        Task<Result<PayloadCreationResult>> CreatePayloadAsync(
            PayloadCreationOptions creationOptions,
            IProgress<PayloadCreationProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Compiles source code into a payload with specified target architecture and optimization settings.
        /// </summary>
        /// <param name="sourceFiles">The source code files to compile</param>
        /// <param name="compilationOptions">Options controlling the compilation process</param>
        /// <param name="progress">Optional progress reporter for tracking compilation progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload compilation result</returns>
        Task<Result<PayloadCompilationResult>> CompilePayloadAsync(
            IEnumerable<string> sourceFiles,
            PayloadCompilationOptions compilationOptions,
            IProgress<PayloadCompilationProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Optimizes a payload for size, performance, or specific target characteristics.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file to optimize</param>
        /// <param name="optimizationOptions">Options controlling the optimization process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload optimization result</returns>
        Task<Result<PayloadOptimizationResult>> OptimizePayloadAsync(
            string payloadPath,
            PayloadOptimizationOptions optimizationOptions,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Caches frequently used payloads for improved performance.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file to cache</param>
        /// <param name="cacheOptions">Options controlling the caching behavior</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the payload caching result</returns>
        Task<Result<PayloadCacheResult>> CachePayloadAsync(
            string payloadPath,
            PayloadCacheOptions? cacheOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a cached payload if available, otherwise loads from disk.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the cached payload retrieval result</returns>
        Task<Result<LoadedPayload>> GetCachedPayloadAsync(
            string payloadPath,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears the payload cache to free memory or force reload of payloads.
        /// </summary>
        /// <param name="payloadPath">Optional specific payload to remove from cache, or null to clear all</param>
        /// <returns>A result indicating the success of the cache clear operation</returns>
        Result<bool> ClearPayloadCache(string? payloadPath = null);

        /// <summary>
        /// Gets information about the current payload cache status and statistics.
        /// </summary>
        /// <returns>Information about the payload cache</returns>
        PayloadCacheInfo GetCacheInfo();

        /// <summary>
        /// Estimates the memory usage of a payload before loading it.
        /// </summary>
        /// <param name="payloadPath">The path to the payload file</param>
        /// <returns>The estimated memory usage in bytes</returns>
        Task<long> EstimatePayloadMemoryUsageAsync(string payloadPath);
    }

    /// <summary>
    /// Represents the result of a payload scanning operation.
    /// </summary>
    public record PayloadScanResult(
        List<DiscoveredPayload> DiscoveredPayloads,
        int DirectoriesScanned,
        int FilesScanned,
        TimeSpan ScanDuration,
        Dictionary<string, object> ScanStatistics);

    /// <summary>
    /// Represents progress information for payload scanning operations.
    /// </summary>
    public record PayloadScanProgress(
        int DirectoriesScanned,
        int TotalDirectories,
        int FilesScanned,
        string CurrentDirectory,
        double PercentComplete);

    /// <summary>
    /// Represents a discovered payload during scanning operations.
    /// </summary>
    public record DiscoveredPayload(
        string FilePath,
        string Name,
        PayloadType Type,
        long Size,
        DateTime LastModified,
        string? Version,
        string? Description,
        PayloadMetadata Metadata);

    /// <summary>
    /// Represents a loaded payload with its data and metadata.
    /// </summary>
    public record LoadedPayload(
        byte[] Data,
        PayloadMetadata Metadata,
        string FilePath,
        long FileSize,
        DateTime LoadTime,
        string Checksum);

    /// <summary>
    /// Represents the result of payload validation operations.
    /// </summary>
    public record PayloadValidationResult(
        bool IsValid,
        List<string> ValidationErrors,
        List<string> ValidationWarnings,
        PayloadSecurityInfo SecurityInfo,
        Dictionary<string, object> ValidationMetrics);

    /// <summary>
    /// Represents the result of payload analysis operations.
    /// </summary>
    public record PayloadAnalysisResult(
        PayloadMetadata Metadata,
        List<string> Dependencies,
        CompatibilityInfo Compatibility,
        PerformanceCharacteristics Performance,
        Dictionary<string, object> AnalysisData);

    /// <summary>
    /// Represents the result of payload creation operations.
    /// </summary>
    public record PayloadCreationResult(
        string PayloadPath,
        long PayloadSize,
        TimeSpan CreationTime,
        string Checksum,
        PayloadMetadata Metadata);

    /// <summary>
    /// Represents progress information for payload creation operations.
    /// </summary>
    public record PayloadCreationProgress(
        string CurrentStep,
        double PercentComplete,
        TimeSpan Elapsed,
        TimeSpan EstimatedRemaining);

    /// <summary>
    /// Represents the result of payload compilation operations.
    /// </summary>
    public record PayloadCompilationResult(
        string CompiledPayloadPath,
        long PayloadSize,
        TimeSpan CompilationTime,
        List<string> CompilerMessages,
        CompilationStatistics Statistics);

    /// <summary>
    /// Represents progress information for payload compilation operations.
    /// </summary>
    public record PayloadCompilationProgress(
        string CurrentFile,
        int FilesCompiled,
        int TotalFiles,
        double PercentComplete,
        string CompilerOutput);

    /// <summary>
    /// Represents the result of payload optimization operations.
    /// </summary>
    public record PayloadOptimizationResult(
        string OptimizedPayloadPath,
        long OriginalSize,
        long OptimizedSize,
        double CompressionRatio,
        TimeSpan OptimizationTime,
        OptimizationStatistics Statistics);

    /// <summary>
    /// Represents the result of payload caching operations.
    /// </summary>
    public record PayloadCacheResult(
        bool IsCached,
        string CacheKey,
        long CacheSize,
        DateTime CacheTime);

    /// <summary>
    /// Represents information about the payload cache.
    /// </summary>
    public record PayloadCacheInfo(
        int CachedPayloads,
        long TotalCacheSize,
        long MaxCacheSize,
        double CacheHitRatio,
        DateTime LastCleanup);

    /// <summary>
    /// Metadata associated with a payload.
    /// </summary>
    public record PayloadMetadata(
        string Name,
        string? Version,
        string? Description,
        string? Author,
        DateTime CreationDate,
        PayloadType Type,
        string TargetArchitecture,
        uint EntryPoint,
        uint LoadAddress,
        Dictionary<string, string> CustomProperties);

    /// <summary>
    /// Security information about a payload.
    /// </summary>
    public record PayloadSecurityInfo(
        bool IsSigned,
        bool IsEncrypted,
        List<string> SecurityFlags,
        string? SignatureInfo,
        SecurityRiskLevel RiskLevel);

    /// <summary>
    /// Compatibility information for a payload.
    /// </summary>
    public record CompatibilityInfo(
        List<string> SupportedDevices,
        List<string> RequiredFeatures,
        string MinimumFirmwareVersion,
        Dictionary<string, object> Constraints);

    /// <summary>
    /// Performance characteristics of a payload.
    /// </summary>
    public record PerformanceCharacteristics(
        uint MemoryRequirement,
        uint ExecutionTime,
        uint CpuUsage,
        Dictionary<string, object> Benchmarks);

    /// <summary>
    /// Statistics from payload compilation operations.
    /// </summary>
    public record CompilationStatistics(
        int SourceFiles,
        int LinesOfCode,
        int Warnings,
        int Errors,
        Dictionary<string, object> Metrics);

    /// <summary>
    /// Statistics from payload optimization operations.
    /// </summary>
    public record OptimizationStatistics(
        int OptimizationsApplied,
        Dictionary<string, double> OptimizationBreakdown,
        Dictionary<string, object> Metrics);

    /// <summary>
    /// Options for controlling payload scanning operations.
    /// </summary>
    public record PayloadScanOptions(
        bool IncludeSubdirectories = true,
        string[] FileExtensions = null!,
        bool ValidatePayloads = true,
        bool ExtractMetadata = true,
        int MaxConcurrency = 4,
        TimeSpan Timeout = default)
    {
        public PayloadScanOptions() : this(true, new[] { ".bin", ".hex", ".elf" }, true, true, 4, TimeSpan.FromMinutes(5)) { }
    }

    /// <summary>
    /// Options for controlling payload loading operations.
    /// </summary>
    public record PayloadLoadOptions(
        bool ValidateChecksum = true,
        bool CachePayload = true,
        bool ExtractMetadata = true,
        int BufferSize = 8192);

    /// <summary>
    /// Options for controlling payload validation operations.
    /// </summary>
    public record PayloadValidationOptions(
        bool CheckFormat = true,
        bool CheckSecurity = true,
        bool CheckCompatibility = true,
        bool DeepValidation = false,
        TimeSpan Timeout = default)
    {
        public PayloadValidationOptions() : this(true, true, true, false, TimeSpan.FromMinutes(2)) { }
    }

    /// <summary>
    /// Options for controlling payload analysis operations.
    /// </summary>
    public record PayloadAnalysisOptions(
        bool AnalyzeDependencies = true,
        bool AnalyzePerformance = true,
        bool AnalyzeCompatibility = true,
        bool DeepAnalysis = false);

    /// <summary>
    /// Options for controlling payload creation operations.
    /// </summary>
    public record PayloadCreationOptions(
        string OutputPath,
        PayloadType Type,
        string TargetArchitecture,
        uint LoadAddress,
        uint EntryPoint,
        Dictionary<string, object>? CustomOptions = null);

    /// <summary>
    /// Options for controlling payload compilation operations.
    /// </summary>
    public record PayloadCompilationOptions(
        string OutputPath,
        string TargetArchitecture,
        OptimizationLevel Optimization,
        bool GenerateDebugInfo,
        Dictionary<string, string>? CompilerFlags = null);

    /// <summary>
    /// Options for controlling payload optimization operations.
    /// </summary>
    public record PayloadOptimizationOptions(
        string OutputPath,
        OptimizationType[] OptimizationTypes,
        bool PreserveDebugInfo = false,
        Dictionary<string, object>? CustomOptions = null);

    /// <summary>
    /// Options for controlling payload caching behavior.
    /// </summary>
    public record PayloadCacheOptions(
        TimeSpan CacheExpiry = default,
        bool CompressCache = true,
        int MaxCacheSize = 100 * 1024 * 1024) // 100MB default
    {
        public PayloadCacheOptions() : this(TimeSpan.FromHours(24), true, 100 * 1024 * 1024) { }
    }

    /// <summary>
    /// Enumeration of payload types.
    /// </summary>
    public enum PayloadType
    {
        /// <summary>
        /// Unknown or unrecognized payload type.
        /// </summary>
        Unknown,

        /// <summary>
        /// Binary executable payload.
        /// </summary>
        Binary,

        /// <summary>
        /// Shellcode payload.
        /// </summary>
        Shellcode,

        /// <summary>
        /// Stager payload for multi-stage operations.
        /// </summary>
        Stager,

        /// <summary>
        /// Memory dump payload.
        /// </summary>
        MemoryDump,

        /// <summary>
        /// Configuration or data payload.
        /// </summary>
        Data,

        /// <summary>
        /// Script or interpreted payload.
        /// </summary>
        Script
    }

    /// <summary>
    /// Enumeration of security risk levels.
    /// </summary>
    public enum SecurityRiskLevel
    {
        /// <summary>
        /// Low security risk.
        /// </summary>
        Low,

        /// <summary>
        /// Medium security risk.
        /// </summary>
        Medium,

        /// <summary>
        /// High security risk.
        /// </summary>
        High,

        /// <summary>
        /// Critical security risk.
        /// </summary>
        Critical
    }

    /// <summary>
    /// Enumeration of optimization levels.
    /// </summary>
    public enum OptimizationLevel
    {
        /// <summary>
        /// No optimization.
        /// </summary>
        None,

        /// <summary>
        /// Basic optimization.
        /// </summary>
        Basic,

        /// <summary>
        /// Standard optimization.
        /// </summary>
        Standard,

        /// <summary>
        /// Aggressive optimization.
        /// </summary>
        Aggressive
    }

    /// <summary>
    /// Enumeration of optimization types.
    /// </summary>
    public enum OptimizationType
    {
        /// <summary>
        /// Size optimization.
        /// </summary>
        Size,

        /// <summary>
        /// Speed optimization.
        /// </summary>
        Speed,

        /// <summary>
        /// Memory usage optimization.
        /// </summary>
        Memory,

        /// <summary>
        /// Compression optimization.
        /// </summary>
        Compression
    }
}