using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using S7.Core.Abstractions.Configuration;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Represents a single memory section to be dumped.
    /// </summary>
    public record MemorySection
    {
        /// <summary>
        /// Gets the name/description of this memory section.
        /// </summary>
        [Required]
        public string Name { get; init; } = string.Empty;

        /// <summary>
        /// Gets the starting memory address for this section.
        /// </summary>
        [Required]
        [Range(0, uint.MaxValue)]
        public uint Address { get; init; }

        /// <summary>
        /// Gets the length of memory to dump in bytes for this section.
        /// </summary>
        [Required]
        [Range(1, uint.MaxValue)]
        public uint Length { get; init; }

        /// <summary>
        /// Gets optional metadata for this section.
        /// </summary>
        public string? Metadata { get; init; }
    }

    /// <summary>
    /// Command for performing memory dump operations on a PLC.
    /// Supports dumping single or multiple memory sections sequentially.
    /// </summary>
    public class MemoryDumpCommand : ICommand<MemoryDumpResult>
    {
        /// <summary>
        /// Gets the correlation ID for tracking this command execution.
        /// </summary>
        public string CorrelationId { get; init; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets the starting memory address for the dump operation.
        /// Only used when MemorySections is null or empty.
        /// </summary>
        [Range(0, uint.MaxValue)]
        public uint Address { get; init; }

        /// <summary>
        /// Gets the length of memory to dump in bytes.
        /// Only used when MemorySections is null or empty.
        /// </summary>
        [Range(1, uint.MaxValue)]
        public uint Length { get; init; }

        /// <summary>
        /// Gets the array of memory sections to dump sequentially.
        /// When specified, this takes precedence over Address and Length properties.
        /// </summary>
        public MemorySection[]? MemorySections { get; init; }

        /// <summary>
        /// Gets the path to the payload file to use for the operation.
        /// </summary>
        [Required]
        public string PayloadPath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the output directory path where the dump file will be saved.
        /// </summary>
        [Required]
        public string OutputPath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the communication channel configuration.
        /// </summary>
        [Required]
        public CommunicationChannelConfig ChannelConfig { get; init; } = new();

        /// <summary>
        /// Gets a value indicating whether to overwrite existing dump files.
        /// </summary>
        public bool OverwriteExisting { get; init; } = false;

        /// <summary>
        /// Gets the custom filename for the dump file (optional).
        /// If not specified, a default filename will be generated.
        /// </summary>
        public string? CustomFilename { get; init; }

        /// <summary>
        /// Gets a value indicating whether to perform a handshake before the dump operation.
        /// </summary>
        public bool PerformHandshake { get; init; } = true;

        /// <summary>
        /// Gets the timeout for the entire dump operation.
        /// </summary>
        public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Gets the chunk size for reading memory in bytes.
        /// Larger chunks may be faster but use more memory.
        /// </summary>
        [Range(1, 65536)]
        public uint ChunkSize { get; init; } = 1024;

        /// <summary>
        /// Gets a value indicating whether to verify the dump after completion.
        /// </summary>
        public bool VerifyDump { get; init; } = true;

        /// <summary>
        /// Gets additional metadata to include with the dump.
        /// </summary>
        public string? Metadata { get; init; }
    }

    /// <summary>
    /// Result of a memory dump operation.
    /// </summary>
    public class MemoryDumpResult
    {
        /// <summary>
        /// Gets the path to the generated dump file (single section mode).
        /// </summary>
        public string DumpFilePath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the paths to all generated dump files (multi-section mode).
        /// </summary>
        public List<string> DumpFilePaths { get; init; } = new();

        /// <summary>
        /// Gets the section results for multi-section dumps.
        /// </summary>
        public List<SectionDumpResult>? SectionResults { get; init; }

        /// <summary>
        /// Gets the actual number of bytes dumped.
        /// </summary>
        public uint BytesDumped { get; init; }

        /// <summary>
        /// Gets the starting address that was dumped.
        /// </summary>
        public uint StartAddress { get; init; }

        /// <summary>
        /// Gets the ending address that was dumped.
        /// </summary>
        public uint EndAddress { get; init; }

        /// <summary>
        /// Gets the duration of the dump operation.
        /// </summary>
        public TimeSpan Duration { get; init; }

        /// <summary>
        /// Gets the checksum of the dumped data (if verification was enabled).
        /// </summary>
        public string? Checksum { get; init; }

        /// <summary>
        /// Gets a value indicating whether the dump was verified successfully.
        /// </summary>
        public bool IsVerified { get; init; }

        /// <summary>
        /// Gets additional metadata about the dump operation.
        /// </summary>
        public string? Metadata { get; init; }

        /// <summary>
        /// Gets the timestamp when the dump was created.
        /// </summary>
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;

        /// <summary>
        /// Gets performance metrics for the dump operation.
        /// </summary>
        public DumpPerformanceMetrics? PerformanceMetrics { get; init; }
    }

    /// <summary>
    /// Performance metrics for memory dump operations.
    /// </summary>
    public record DumpPerformanceMetrics
    {
        /// <summary>
        /// Gets the average read speed in bytes per second.
        /// </summary>
        public double AverageReadSpeed { get; init; }

        /// <summary>
        /// Gets the number of read operations performed.
        /// </summary>
        public int ReadOperations { get; init; }

        /// <summary>
        /// Gets the number of retry operations that were needed.
        /// </summary>
        public int RetryOperations { get; init; }

        /// <summary>
        /// Gets the time spent on handshake operations.
        /// </summary>
        public TimeSpan HandshakeTime { get; init; }

        /// <summary>
        /// Gets the time spent on actual data transfer.
        /// </summary>
        public TimeSpan DataTransferTime { get; init; }

        /// <summary>
        /// Gets the time spent on verification (if enabled).
        /// </summary>
        public TimeSpan VerificationTime { get; init; }
    }

    /// <summary>
    /// Result of dumping a single memory section.
    /// </summary>
    public class SectionDumpResult
    {
        /// <summary>
        /// Gets the name of the section that was dumped.
        /// </summary>
        public string SectionName { get; init; } = string.Empty;

        /// <summary>
        /// Gets the starting address of the section.
        /// </summary>
        public uint StartAddress { get; init; }

        /// <summary>
        /// Gets the length of the section in bytes.
        /// </summary>
        public uint Length { get; init; }

        /// <summary>
        /// Gets the path to the dump file for this section.
        /// </summary>
        public string DumpFilePath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the number of bytes actually dumped for this section.
        /// </summary>
        public uint BytesDumped { get; init; }

        /// <summary>
        /// Gets the duration of dumping this section.
        /// </summary>
        public TimeSpan Duration { get; init; }

        /// <summary>
        /// Gets the checksum of this section's data (if verification was enabled).
        /// </summary>
        public string? Checksum { get; init; }

        /// <summary>
        /// Gets a value indicating whether this section was verified successfully.
        /// </summary>
        public bool IsVerified { get; init; }

        /// <summary>
        /// Gets whether the client acknowledged this section completion.
        /// </summary>
        public bool ClientAcknowledged { get; init; }

        /// <summary>
        /// Gets the timestamp when acknowledgment was received.
        /// </summary>
        public DateTime? AcknowledgmentTime { get; init; }
    }
}