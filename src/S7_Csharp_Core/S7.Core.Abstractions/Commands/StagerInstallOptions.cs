using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Validation;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Options for stager installation command handler operations.
    /// </summary>
    public class StagerInstallOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the path to the stager payload file.
        /// </summary>
        [Required(ErrorMessage = "Payload path is required")]
        [FilePath(AllowedExtensions = new[] { "bin", "hex", "elf", "s" }, ErrorMessage = "Stager payload file must exist and have a valid extension (.bin, .hex, .elf, .s)")]
        public string PayloadPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the communication channel configuration.
        /// </summary>
        [Required(ErrorMessage = "Channel configuration is required")]
        public CommunicationChannelConfig ChannelConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets the power controller configuration (optional).
        /// If provided, power cycling will be performed as part of the installation.
        /// </summary>
        public PowerControllerConfig? PowerConfig { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to perform a handshake before installation.
        /// </summary>
        public bool PerformHandshake { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to retrieve version information after installation.
        /// </summary>
        public bool GetVersionInfo { get; set; } = false;

        /// <summary>
        /// Gets or sets the timeout for the entire installation operation in milliseconds.
        /// Overrides the base TimeoutMs property with installation-specific default.
        /// </summary>
        [Timeout(MinTimeoutMs = 10000, MaxTimeoutMs = 1800000, ErrorMessage = "Installation timeout must be between 10 seconds and 30 minutes")]
        public new int TimeoutMs { get; set; } = 300000; // 5 minutes default for stager installation

        /// <summary>
        /// Gets or sets a value indicating whether to perform power cycling before installation.
        /// </summary>
        public bool PowerCycleBeforeInstall { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether to perform power cycling after installation.
        /// </summary>
        public bool PowerCycleAfterInstall { get; set; } = false;

        /// <summary>
        /// Gets or sets the number of retry attempts for the installation.
        /// </summary>
        [Range(0, 10, ErrorMessage = "Retry attempts must be between 0 and 10")]
        public int RetryAttempts { get; set; } = 3;

        /// <summary>
        /// Gets or sets the delay between retry attempts in milliseconds.
        /// </summary>
        [Range(500, 30000, ErrorMessage = "Retry delay must be between 500 and 30000 milliseconds")]
        public int RetryDelayMs { get; set; } = 2000;

        /// <summary>
        /// Gets or sets a value indicating whether to verify the stager installation.
        /// </summary>
        public bool VerifyInstallation { get; set; } = true;

        /// <summary>
        /// Gets or sets additional installation options as a JSON string.
        /// </summary>
        [StringLength(1000, ErrorMessage = "Installation options cannot exceed 1000 characters")]
        public string? InstallationOptions { get; set; }

        /// <summary>
        /// Gets or sets the target installation address (optional).
        /// If not specified, the stager will determine the appropriate address.
        /// </summary>
        [HexAddress(MinValue = 0x1000, MaxValue = 0xFFFFFFFF, AllowEmpty = true, ErrorMessage = "Installation address must be a valid 32-bit hex address (0x1000-0xFFFFFFFF)")]
        public uint? TargetAddress { get; set; }

        /// <summary>
        /// Gets or sets the maximum payload size allowed in bytes.
        /// </summary>
        [NumericRange(1024, int.MaxValue, Alignment = 1024, ErrorMessage = "Maximum payload size must be at least 1024 bytes and aligned to 1KB boundary")]
        public int MaxPayloadSize { get; set; } = 1048576; // 1MB default

        /// <summary>
        /// Gets or sets a value indicating whether to backup existing memory before installation.
        /// </summary>
        public bool BackupBeforeInstall { get; set; } = true;

        /// <summary>
        /// Gets or sets the backup file path (optional).
        /// If not specified, a default backup filename will be generated.
        /// </summary>
        [FilePath(MustExist = false, AllowEmpty = true, AllowedExtensions = new[] { "bin", "bak", "dump" }, ErrorMessage = "Backup file path must be valid and have extension (.bin, .bak, .dump)")]
        public string? BackupFilePath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to perform a memory integrity check after installation.
        /// </summary>
        public bool PerformIntegrityCheck { get; set; } = true;

        /// <summary>
        /// Gets or sets the expected stager checksum for verification (optional).
        /// </summary>
        [RegularExpression(@"^[a-fA-F0-9]{32,128}$", ErrorMessage = "Checksum must be a valid hexadecimal string (32-128 characters)")]
        public string? ExpectedChecksum { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable verbose logging during installation.
        /// </summary>
        public bool VerboseLogging { get; set; } = false;

        /// <summary>
        /// Gets or sets the installation mode.
        /// </summary>
        public StagerInstallationMode InstallationMode { get; set; } = StagerInstallationMode.Standard;

        /// <summary>
        /// Gets or sets the power cycle delay in milliseconds when power cycling is enabled.
        /// </summary>
        [Range(1000, 60000, ErrorMessage = "Power cycle delay must be between 1 and 60 seconds")]
        public int PowerCycleDelayMs { get; set; } = 5000;

        /// <summary>
        /// Validates the stager installation options and returns validation results.
        /// </summary>
        /// <returns>A collection of validation results</returns>
        public override System.Collections.Generic.IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate()
        {
            var results = base.Validate().ToList();

            // Validate payload file size
            if (!string.IsNullOrEmpty(PayloadPath) && File.Exists(PayloadPath))
            {
                var fileInfo = new FileInfo(PayloadPath);
                if (fileInfo.Length > MaxPayloadSize)
                {
                    results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                        $"Payload file size ({fileInfo.Length} bytes) exceeds maximum allowed size ({MaxPayloadSize} bytes)",
                        new[] { nameof(PayloadPath), nameof(MaxPayloadSize) }));
                }

                if (fileInfo.Length == 0)
                {
                    results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                        "Payload file is empty",
                        new[] { nameof(PayloadPath) }));
                }
            }

            // Validate power cycling configuration
            if ((PowerCycleBeforeInstall || PowerCycleAfterInstall) && PowerConfig == null)
            {
                results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                    "Power controller configuration is required when power cycling is enabled",
                    new[] { nameof(PowerConfig), nameof(PowerCycleBeforeInstall), nameof(PowerCycleAfterInstall) }));
            }

            // Validate backup configuration
            if (BackupBeforeInstall && !string.IsNullOrEmpty(BackupFilePath))
            {
                try
                {
                    var backupDir = Path.GetDirectoryName(BackupFilePath);
                    if (!string.IsNullOrEmpty(backupDir) && !Directory.Exists(backupDir))
                    {
                        results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                            $"Backup directory does not exist: {backupDir}",
                            new[] { nameof(BackupFilePath) }));
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                        $"Invalid backup file path: {ex.Message}",
                        new[] { nameof(BackupFilePath) }));
                }
            }

            // Validate installation options JSON format if provided
            if (!string.IsNullOrEmpty(InstallationOptions))
            {
                try
                {
                    System.Text.Json.JsonDocument.Parse(InstallationOptions);
                }
                catch (System.Text.Json.JsonException ex)
                {
                    results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                        $"Installation options must be valid JSON: {ex.Message}",
                        new[] { nameof(InstallationOptions) }));
                }
            }

            // Validate retry configuration consistency
            if (RetryAttempts > 0 && RetryDelayMs <= 0)
            {
                results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                    "Retry delay must be greater than 0 when retry attempts are configured",
                    new[] { nameof(RetryAttempts), nameof(RetryDelayMs) }));
            }

            return results;
        }
    }

    /// <summary>
    /// Defines the installation modes for stager deployment.
    /// </summary>
    public enum StagerInstallationMode
    {
        /// <summary>
        /// Standard installation mode with default settings.
        /// </summary>
        Standard = 0,

        /// <summary>
        /// Fast installation mode with minimal verification.
        /// </summary>
        Fast = 1,

        /// <summary>
        /// Secure installation mode with enhanced verification and integrity checks.
        /// </summary>
        Secure = 2,

        /// <summary>
        /// Debug installation mode with verbose logging and extended verification.
        /// </summary>
        Debug = 3,

        /// <summary>
        /// Recovery installation mode for restoring from backup or failed installations.
        /// </summary>
        Recovery = 4
    }
}