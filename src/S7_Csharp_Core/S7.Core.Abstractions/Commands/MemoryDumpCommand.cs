using System;
using System.ComponentModel.DataAnnotations;
using S7.Core.Abstractions.Configuration;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Command for performing memory dump operations on a PLC.
    /// This command encapsulates the options required for the operation.
    /// </summary>
    public class MemoryDumpCommand : ICommand<MemoryDumpResult>
    {
        /// <summary>
        /// Gets the options for the memory dump operation.
        /// </summary>
        [Required]
        public MemoryDumpOptions Options { get; }

        /// <summary>
        /// Gets the correlation ID for tracking this command execution.
        /// </summary>
        public string CorrelationId => Options.CorrelationId;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryDumpCommand"/> class.
        /// </summary>
        /// <param name="options">The options for the memory dump operation.</param>
        public MemoryDumpCommand(MemoryDumpOptions options)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options));
        }
    }

    /// <summary>
    /// Result of a memory dump operation.
    /// </summary>
    public class MemoryDumpResult
    {
        /// <summary>
        /// Gets the path to the generated dump file.
        /// </summary>
        public string DumpFilePath { get; init; } = string.Empty;

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
}