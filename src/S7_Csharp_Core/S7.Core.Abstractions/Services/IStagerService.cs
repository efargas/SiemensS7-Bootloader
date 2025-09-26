using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils;
using S7.Core.Abstractions.Commands;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Service interface for stager installation and management operations providing comprehensive stager lifecycle management.
    /// </summary>
    public interface IStagerService
    {
        /// <summary>
        /// Installs a stager payload to the target device asynchronously with comprehensive validation and retry logic.
        /// </summary>
        /// <param name="options">The stager installation configuration options</param>
        /// <param name="progress">Optional progress reporter for tracking installation progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the stager installation operation result</returns>
        Task<Result<StagerInstallResult>> InstallStagerAsync(
            StagerInstallOptions options,
            IProgress<StagerInstallProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Verifies that a stager is correctly installed and operational at the specified address.
        /// </summary>
        /// <param name="installationAddress">The address where the stager was installed</param>
        /// <param name="expectedChecksum">Optional expected checksum for verification</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the verification result</returns>
        Task<Result<StagerVerificationResult>> VerifyStagerInstallationAsync(
            uint installationAddress,
            string? expectedChecksum = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves version and capability information from an installed stager.
        /// </summary>
        /// <param name="installationAddress">The address where the stager is installed</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the stager information retrieval result</returns>
        Task<Result<StagerInfo>> GetStagerInfoAsync(
            uint installationAddress,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Uninstalls a stager from the target device and restores original functionality.
        /// </summary>
        /// <param name="installationAddress">The address where the stager is installed</param>
        /// <param name="restoreOriginal">Whether to restore original code/data</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the stager uninstallation result</returns>
        Task<Result<StagerUninstallResult>> UninstallStagerAsync(
            uint installationAddress,
            bool restoreOriginal = true,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes a command through an installed stager with comprehensive error handling.
        /// </summary>
        /// <param name="installationAddress">The address where the stager is installed</param>
        /// <param name="command">The command to execute</param>
        /// <param name="parameters">Optional command parameters</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        Task<Result<StagerCommandResult>> ExecuteStagerCommandAsync(
            uint installationAddress,
            string command,
            Dictionary<string, object>? parameters = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Scans the target device for existing stager installations.
        /// </summary>
        /// <param name="scanOptions">Options controlling the scan process</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the scan result with found stagers</returns>
        Task<Result<StagerScanResult>> ScanForStagersAsync(
            StagerScanOptions? scanOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing stager installation with a new version or configuration.
        /// </summary>
        /// <param name="installationAddress">The address where the stager is currently installed</param>
        /// <param name="updateOptions">The update configuration options</param>
        /// <param name="progress">Optional progress reporter for tracking update progress</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the stager update result</returns>
        Task<Result<StagerUpdateResult>> UpdateStagerAsync(
            uint installationAddress,
            StagerUpdateOptions updateOptions,
            IProgress<StagerUpdateProgress>? progress = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates stager installation parameters before attempting installation.
        /// </summary>
        /// <param name="options">The stager installation options to validate</param>
        /// <returns>A validation result indicating whether the parameters are valid</returns>
        Result<bool> ValidateInstallationParameters(StagerInstallOptions options);

        /// <summary>
        /// Estimates the time required to complete a stager installation based on the specified parameters.
        /// </summary>
        /// <param name="payloadSize">The size of the stager payload in bytes</param>
        /// <param name="connectionSpeed">The estimated connection speed in bytes per second</param>
        /// <param name="includeVerification">Whether to include verification time in the estimate</param>
        /// <returns>The estimated duration for the installation operation</returns>
        TimeSpan EstimateInstallationDuration(uint payloadSize, int connectionSpeed = 1024, bool includeVerification = true);

        /// <summary>
        /// Gets the optimal installation address for a stager based on target device characteristics.
        /// </summary>
        /// <param name="payloadSize">The size of the stager payload</param>
        /// <param name="deviceInfo">Information about the target device</param>
        /// <returns>The recommended installation address</returns>
        uint GetOptimalInstallationAddress(uint payloadSize, DeviceInfo? deviceInfo = null);
    }

    /// <summary>
    /// Represents the result of a stager installation operation.
    /// </summary>
    public record StagerInstallResult(
        bool IsInstalled,
        uint InstallationAddress,
        string StagerVersion,
        uint StagerSize,
        TimeSpan Duration,
        string Checksum,
        bool IsVerified,
        string? AdditionalHooks,
        InstallationPerformanceMetrics PerformanceMetrics,
        string[]? Warnings);

    /// <summary>
    /// Represents progress information for stager installation operations.
    /// </summary>
    public record StagerInstallProgress(
        uint BytesTransferred,
        uint TotalBytes,
        double PercentComplete,
        TimeSpan Elapsed,
        TimeSpan EstimatedRemaining,
        string CurrentOperation,
        int RetryAttempt);

    /// <summary>
    /// Represents the result of stager verification operations.
    /// </summary>
    public record StagerVerificationResult(
        bool IsValid,
        bool ChecksumMatch,
        bool IsOperational,
        string? DetectedVersion,
        List<string> ValidationErrors,
        Dictionary<string, object> VerificationMetrics);

    /// <summary>
    /// Represents information about an installed stager.
    /// </summary>
    public record StagerInfo(
        string Version,
        uint InstallationAddress,
        uint Size,
        DateTime InstallationTime,
        string[] SupportedCommands,
        Dictionary<string, string> Capabilities,
        StagerStatus Status);

    /// <summary>
    /// Represents the result of stager uninstallation operations.
    /// </summary>
    public record StagerUninstallResult(
        bool IsUninstalled,
        bool OriginalRestored,
        TimeSpan Duration,
        string[]? Warnings);

    /// <summary>
    /// Represents the result of executing a command through a stager.
    /// </summary>
    public record StagerCommandResult(
        bool IsSuccess,
        string? Output,
        int ExitCode,
        TimeSpan ExecutionTime,
        string? ErrorMessage);

    /// <summary>
    /// Represents the result of scanning for existing stagers.
    /// </summary>
    public record StagerScanResult(
        List<DetectedStager> DetectedStagers,
        uint AddressesScanned,
        TimeSpan ScanDuration,
        Dictionary<string, object> ScanMetrics);

    /// <summary>
    /// Represents a detected stager during scanning operations.
    /// </summary>
    public record DetectedStager(
        uint Address,
        string? Version,
        uint Size,
        double Confidence,
        string DetectionMethod);

    /// <summary>
    /// Represents the result of stager update operations.
    /// </summary>
    public record StagerUpdateResult(
        bool IsUpdated,
        string PreviousVersion,
        string NewVersion,
        TimeSpan Duration,
        bool BackupCreated,
        string[]? Warnings);

    /// <summary>
    /// Represents progress information for stager update operations.
    /// </summary>
    public record StagerUpdateProgress(
        uint BytesTransferred,
        uint TotalBytes,
        double PercentComplete,
        TimeSpan Elapsed,
        TimeSpan EstimatedRemaining,
        string CurrentOperation);

    /// <summary>
    /// Options for controlling stager scanning operations.
    /// </summary>
    public record StagerScanOptions(
        uint StartAddress = 0x1000,
        uint EndAddress = 0x10000,
        uint ScanStep = 0x100,
        bool DeepScan = false,
        TimeSpan Timeout = default);

    /// <summary>
    /// Options for controlling stager update operations.
    /// </summary>
    public record StagerUpdateOptions(
        string PayloadPath,
        bool CreateBackup = true,
        bool VerifyUpdate = true,
        int RetryAttempts = 3,
        int RetryDelayMs = 1000);

    /// <summary>
    /// Performance metrics for stager installation operations.
    /// </summary>
    public record InstallationPerformanceMetrics(
        TimeSpan HandshakeTime = default,
        TimeSpan PayloadTransferTime = default,
        TimeSpan VerificationTime = default,
        TimeSpan PowerCycleTime = default,
        int RetryAttempts = 0,
        double AverageTransferSpeed = 0,
        uint TotalBytesTransferred = 0);

    /// <summary>
    /// Information about the target device for stager operations.
    /// </summary>
    public record DeviceInfo(
        string DeviceType,
        string FirmwareVersion,
        uint AvailableMemory,
        Dictionary<string, object> Characteristics);

    /// <summary>
    /// Enumeration of possible stager status values.
    /// </summary>
    public enum StagerStatus
    {
        /// <summary>
        /// Stager status is unknown or could not be determined.
        /// </summary>
        Unknown,

        /// <summary>
        /// Stager is installed and operational.
        /// </summary>
        Active,

        /// <summary>
        /// Stager is installed but not responding.
        /// </summary>
        Inactive,

        /// <summary>
        /// Stager installation is corrupted or partially installed.
        /// </summary>
        Corrupted,

        /// <summary>
        /// Stager is in the process of being updated.
        /// </summary>
        Updating
    }
}