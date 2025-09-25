using System;
using System.ComponentModel.DataAnnotations;
using S7.Core.Abstractions.Configuration;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Command for installing a stager on a PLC.
    /// </summary>
    public class StagerInstallCommand : ICommand<StagerInstallResult>
    {
        /// <summary>
        /// Gets the correlation ID for tracking this command execution.
        /// </summary>
        public string CorrelationId { get; init; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets the path to the stager payload file.
        /// </summary>
        [Required]
        public string PayloadPath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the communication channel configuration.
        /// </summary>
        [Required]
        public CommunicationChannelConfig ChannelConfig { get; init; } = new();

        /// <summary>
        /// Gets the power controller configuration (optional).
        /// If provided, power cycling will be performed as part of the installation.
        /// </summary>
        public PowerControllerConfig? PowerConfig { get; init; }

        /// <summary>
        /// Gets a value indicating whether to perform a handshake before installation.
        /// </summary>
        public bool PerformHandshake { get; init; } = true;

        /// <summary>
        /// Gets a value indicating whether to retrieve version information after installation.
        /// </summary>
        public bool GetVersionInfo { get; init; } = false;

        /// <summary>
        /// Gets the timeout for the entire installation operation.
        /// </summary>
        public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets a value indicating whether to perform power cycling before installation.
        /// </summary>
        public bool PowerCycleBeforeInstall { get; init; } = false;

        /// <summary>
        /// Gets a value indicating whether to perform power cycling after installation.
        /// </summary>
        public bool PowerCycleAfterInstall { get; init; } = false;

        /// <summary>
        /// Gets the number of retry attempts for the installation.
        /// </summary>
        [Range(0, 10)]
        public int RetryAttempts { get; init; } = 3;

        /// <summary>
        /// Gets the delay between retry attempts.
        /// </summary>
        public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(2);

        /// <summary>
        /// Gets a value indicating whether to verify the stager installation.
        /// </summary>
        public bool VerifyInstallation { get; init; } = true;

        /// <summary>
        /// Gets additional installation options as key-value pairs.
        /// </summary>
        public string? InstallationOptions { get; init; }
    }

    /// <summary>
    /// Result of a stager installation operation.
    /// </summary>
    public class StagerInstallResult
    {
        /// <summary>
        /// Gets a value indicating whether the installation was successful.
        /// </summary>
        public bool IsInstalled { get; init; }

        /// <summary>
        /// Gets the version information of the installed stager (if available).
        /// </summary>
        public string? StagerVersion { get; init; }

        /// <summary>
        /// Gets the installation address where the stager was loaded.
        /// </summary>
        public uint InstallationAddress { get; init; }

        /// <summary>
        /// Gets the size of the installed stager in bytes.
        /// </summary>
        public uint StagerSize { get; init; }

        /// <summary>
        /// Gets the duration of the installation operation.
        /// </summary>
        public TimeSpan Duration { get; init; }

        /// <summary>
        /// Gets the checksum of the installed stager.
        /// </summary>
        public string? Checksum { get; init; }

        /// <summary>
        /// Gets a value indicating whether the installation was verified.
        /// </summary>
        public bool IsVerified { get; init; }

        /// <summary>
        /// Gets information about any additional hooks that were installed.
        /// </summary>
        public string? AdditionalHooks { get; init; }

        /// <summary>
        /// Gets the timestamp when the installation was completed.
        /// </summary>
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;

        /// <summary>
        /// Gets performance metrics for the installation operation.
        /// </summary>
        public InstallationPerformanceMetrics? PerformanceMetrics { get; init; }

        /// <summary>
        /// Gets any warnings or informational messages from the installation.
        /// </summary>
        public string[]? Warnings { get; init; }
    }

    /// <summary>
    /// Performance metrics for stager installation operations.
    /// </summary>
    public record InstallationPerformanceMetrics
    {
        /// <summary>
        /// Gets the time spent on handshake operations.
        /// </summary>
        public TimeSpan HandshakeTime { get; init; }

        /// <summary>
        /// Gets the time spent on power cycling operations.
        /// </summary>
        public TimeSpan PowerCycleTime { get; init; }

        /// <summary>
        /// Gets the time spent on payload transfer.
        /// </summary>
        public TimeSpan PayloadTransferTime { get; init; }

        /// <summary>
        /// Gets the time spent on installation verification.
        /// </summary>
        public TimeSpan VerificationTime { get; init; }

        /// <summary>
        /// Gets the number of retry attempts that were made.
        /// </summary>
        public int RetryAttempts { get; init; }

        /// <summary>
        /// Gets the average transfer speed in bytes per second.
        /// </summary>
        public double AverageTransferSpeed { get; init; }

        /// <summary>
        /// Gets the total number of bytes transferred.
        /// </summary>
        public uint TotalBytesTransferred { get; init; }
    }
}