using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Models;

namespace S7.Core.Abstractions.Repositories;

/// <summary>
/// Specialized repository interface for memory dump operations.
/// Provides high-level abstractions for managing PLC memory dumps and related operations.
/// </summary>
public interface IMemoryDumpRepository : IRepository<MemoryDump, string>
{
    /// <summary>
    /// Creates a new memory dump from the specified data source.
    /// </summary>
    /// <param name="sourceFilePath">The path to the source file containing the memory dump</param>
    /// <param name="dumpMetadata">Metadata about the memory dump</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The created memory dump entity</returns>
    Task<MemoryDump> CreateMemoryDumpAsync(string sourceFilePath, MemoryDumpMetadata dumpMetadata, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a specific memory region from a dump file.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="startAddress">The starting memory address to read</param>
    /// <param name="length">The number of bytes to read</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>The memory data at the specified region</returns>
    Task<ReadOnlyMemory<byte>> ReadMemoryRegionAsync(string dumpId, long startAddress, int length, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes data to a specific memory region in a dump file.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="startAddress">The starting memory address to write</param>
    /// <param name="data">The data to write</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task WriteMemoryRegionAsync(string dumpId, long startAddress, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compares two memory dumps and identifies differences.
    /// </summary>
    /// <param name="firstDumpId">The identifier of the first memory dump</param>
    /// <param name="secondDumpId">The identifier of the second memory dump</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A collection of memory differences between the dumps</returns>
    Task<IEnumerable<MemoryDifference>> CompareMemoryDumpsAsync(string firstDumpId, string secondDumpId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Searches for a specific byte pattern within a memory dump.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="pattern">The byte pattern to search for</param>
    /// <param name="startAddress">The starting address for the search (optional)</param>
    /// <param name="endAddress">The ending address for the search (optional)</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A collection of addresses where the pattern was found</returns>
    Task<IEnumerable<long>> SearchPatternAsync(string dumpId, ReadOnlyMemory<byte> pattern, long? startAddress = null, long? endAddress = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Extracts a specific memory segment from a dump and saves it as a separate file.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="startAddress">The starting address of the segment</param>
    /// <param name="length">The length of the segment in bytes</param>
    /// <param name="outputPath">The path where the extracted segment should be saved</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task ExtractMemorySegmentAsync(string dumpId, long startAddress, int length, string outputPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the integrity of a memory dump file.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A validation result indicating whether the dump is valid</returns>
    Task<MemoryDumpValidationResult> ValidateDumpIntegrityAsync(string dumpId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets statistics about a memory dump, such as size, address ranges, and data distribution.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>Statistical information about the memory dump</returns>
    Task<MemoryDumpStatistics> GetDumpStatisticsAsync(string dumpId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates an index of the memory dump for faster searching and analysis.
    /// </summary>
    /// <param name="dumpId">The unique identifier of the memory dump</param>
    /// <param name="indexOptions">Options for creating the index</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    Task CreateDumpIndexAsync(string dumpId, MemoryDumpIndexOptions? indexOptions = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents a memory dump entity in the repository.
/// </summary>
public record MemoryDump(
    string Id,
    string FilePath,
    MemoryDumpMetadata Metadata,
    DateTime CreatedAt,
    DateTime ModifiedAt,
    long Size,
    string? Checksum = null)
{
    /// <summary>
    /// Gets the base address of the memory dump.
    /// </summary>
    public long BaseAddress => Metadata.BaseAddress;

    /// <summary>
    /// Gets the end address of the memory dump.
    /// </summary>
    public long EndAddress => BaseAddress + Size - 1;

    /// <summary>
    /// Gets the device information associated with this dump.
    /// </summary>
    public string DeviceInfo => Metadata.DeviceInfo;
}

/// <summary>
/// Contains metadata about a memory dump.
/// </summary>
public record MemoryDumpMetadata(
    long BaseAddress,
    string DeviceInfo,
    string FirmwareVersion,
    DateTime DumpTimestamp,
    Dictionary<string, object>? ExtendedProperties = null);

/// <summary>
/// Represents a difference between two memory locations.
/// </summary>
public record MemoryDifference(
    long Address,
    byte OriginalValue,
    byte NewValue,
    string Description = "");

/// <summary>
/// Contains the result of a memory dump validation operation.
/// </summary>
public record MemoryDumpValidationResult(
    bool IsValid,
    string? ErrorMessage = null,
    IEnumerable<string>? Warnings = null,
    Dictionary<string, object>? ValidationDetails = null);

/// <summary>
/// Contains statistical information about a memory dump.
/// </summary>
public record MemoryDumpStatistics(
    long TotalSize,
    long BaseAddress,
    long EndAddress,
    int UniqueByteValues,
    Dictionary<byte, long> ByteFrequency,
    IEnumerable<MemoryRegion> IdentifiedRegions);

/// <summary>
/// Represents a region of memory with specific characteristics.
/// </summary>
public record MemoryRegion(
    long StartAddress,
    long EndAddress,
    string RegionType,
    string Description = "",
    Dictionary<string, object>? Properties = null)
{
    /// <summary>
    /// Gets the size of this memory region in bytes.
    /// </summary>
    public long Size => EndAddress - StartAddress + 1;
}

/// <summary>
/// Options for creating a memory dump index.
/// </summary>
public record MemoryDumpIndexOptions(
    bool IndexBytePatterns = true,
    bool IndexStringPatterns = true,
    int MinPatternLength = 4,
    int MaxPatternLength = 64,
    bool CreateAddressIndex = true,
    Dictionary<string, object>? CustomIndexOptions = null);