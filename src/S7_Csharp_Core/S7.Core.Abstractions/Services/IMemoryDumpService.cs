using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils;
using S7.Core.Abstractions.Commands;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Service interface for memory dump operations providing comprehensive memory extraction and validation capabilities.
    /// </summary>
    public interface IMemoryDumpService
    {
        /// <summary>
        /// Dumps memory from the specified address range asynchronously with progress reporting.
        /// </summary>
        /// <param name="options">The memory dump configuration options</param>
        /// <param name="progress">Optional progress reporter for tracking dump progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the memory dump operation result</returns>
        Task<Result<MemoryDumpResult>> DumpMemoryAsync(
            MemoryDumpOptions options,
            IProgress<MemoryDumpProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates the integrity of a memory dump by performing checksum verification and consistency checks.
        /// </summary>
        /// <param name="dumpData">The memory dump data to validate</param>
        /// <param name="expectedChecksum">Optional expected checksum for validation</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the validation result</returns>
        Task<Result<MemoryDumpValidationResult>> ValidateDumpIntegrityAsync(
            byte[] dumpData,
            string? expectedChecksum = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Compares two memory dumps and identifies differences between them.
        /// </summary>
        /// <param name="originalDump">The original memory dump data</param>
        /// <param name="comparisonDump">The comparison memory dump data</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the comparison result with identified differences</returns>
        Task<Result<MemoryDumpComparisonResult>> CompareDumpsAsync(
            byte[] originalDump,
            byte[] comparisonDump,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Saves a memory dump to the specified file path with optional compression and metadata.
        /// </summary>
        /// <param name="dumpData">The memory dump data to save</param>
        /// <param name="filePath">The target file path for saving the dump</param>
        /// <param name="metadata">Optional metadata to include with the dump</param>
        /// <param name="compress">Whether to compress the dump data</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the save operation result</returns>
        Task<Result<string>> SaveDumpAsync(
            byte[] dumpData,
            string filePath,
            MemoryDumpMetadata? metadata = null,
            bool compress = true,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Loads a memory dump from the specified file path with automatic decompression and metadata extraction.
        /// </summary>
        /// <param name="filePath">The file path of the dump to load</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the load operation result with dump data and metadata</returns>
        Task<Result<LoadedMemoryDump>> LoadDumpAsync(
            string filePath,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Analyzes a memory dump to identify patterns, structures, and potential points of interest.
        /// </summary>
        /// <param name="dumpData">The memory dump data to analyze</param>
        /// <param name="analysisOptions">Options controlling the analysis process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the analysis result with identified patterns and structures</returns>
        Task<Result<MemoryDumpAnalysisResult>> AnalyzeDumpAsync(
            byte[] dumpData,
            MemoryDumpAnalysisOptions? analysisOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Estimates the time required to complete a memory dump operation based on the specified parameters.
        /// </summary>
        /// <param name="startAddress">The starting address for the dump</param>
        /// <param name="length">The length of memory to dump</param>
        /// <param name="chunkSize">The chunk size for the dump operation</param>
        /// <returns>The estimated duration for the dump operation</returns>
        TimeSpan EstimateDumpDuration(uint startAddress, uint length, int chunkSize = 1024);

        /// <summary>
        /// Gets the optimal chunk size for memory dump operations based on current system conditions.
        /// </summary>
        /// <param name="totalLength">The total length of memory to dump</param>
        /// <param name="connectionSpeed">The estimated connection speed in bytes per second</param>
        /// <returns>The recommended chunk size for optimal performance</returns>
        int GetOptimalChunkSize(uint totalLength, int connectionSpeed = 1024);

        /// <summary>
        /// Validates memory dump parameters before starting the dump operation.
        /// </summary>
        /// <param name="options">The memory dump options to validate</param>
        /// <returns>A validation result indicating whether the parameters are valid</returns>
        Result<bool> ValidateDumpParameters(MemoryDumpOptions options);
    }

    /// <summary>
    /// Represents the result of a memory dump operation.
    /// </summary>
    public record MemoryDumpResult(
        byte[] Data,
        uint StartAddress,
        uint Length,
        string Checksum,
        TimeSpan Duration,
        MemoryDumpMetadata Metadata);

    /// <summary>
    /// Represents progress information for memory dump operations.
    /// </summary>
    public record MemoryDumpProgress(
        uint BytesRead,
        uint TotalBytes,
        double PercentComplete,
        TimeSpan Elapsed,
        TimeSpan EstimatedRemaining,
        string CurrentOperation);

    /// <summary>
    /// Represents the result of memory dump validation.
    /// </summary>
    public record MemoryDumpValidationResult(
        bool IsValid,
        string? ChecksumMatch,
        List<string> ValidationErrors,
        Dictionary<string, object> ValidationMetrics);

    /// <summary>
    /// Represents the result of comparing two memory dumps.
    /// </summary>
    public record MemoryDumpComparisonResult(
        bool AreIdentical,
        List<MemoryDifference> Differences,
        double SimilarityPercentage,
        Dictionary<string, object> ComparisonMetrics);

    /// <summary>
    /// Represents a difference found between two memory dumps.
    /// </summary>
    public record MemoryDifference(
        uint Offset,
        byte OriginalValue,
        byte ComparisonValue,
        string Description);

    /// <summary>
    /// Represents metadata associated with a memory dump.
    /// </summary>
    public record MemoryDumpMetadata(
        DateTime Timestamp,
        string DeviceInfo,
        string Version,
        Dictionary<string, string> CustomProperties);

    /// <summary>
    /// Represents a loaded memory dump with its associated metadata.
    /// </summary>
    public record LoadedMemoryDump(
        byte[] Data,
        MemoryDumpMetadata Metadata,
        string FilePath,
        long FileSize);

    /// <summary>
    /// Represents the result of memory dump analysis.
    /// </summary>
    public record MemoryDumpAnalysisResult(
        List<MemoryPattern> IdentifiedPatterns,
        List<MemoryStructure> DetectedStructures,
        Dictionary<string, object> Statistics,
        List<string> Recommendations);

    /// <summary>
    /// Represents a pattern identified in memory dump analysis.
    /// </summary>
    public record MemoryPattern(
        string Name,
        uint StartOffset,
        uint Length,
        byte[] Pattern,
        double Confidence,
        string Description);

    /// <summary>
    /// Represents a structure detected in memory dump analysis.
    /// </summary>
    public record MemoryStructure(
        string Type,
        uint Offset,
        uint Size,
        Dictionary<string, object> Fields,
        string Description);

    /// <summary>
    /// Options for controlling memory dump analysis.
    /// </summary>
    public record MemoryDumpAnalysisOptions(
        bool DetectPatterns = true,
        bool AnalyzeStructures = true,
        bool GenerateStatistics = true,
        int MaxPatternLength = 256,
        double MinPatternConfidence = 0.8);
}