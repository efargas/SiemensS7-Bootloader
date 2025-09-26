using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using S7.Core.Abstractions.Validation;
using ValidationResult = System.ComponentModel.DataAnnotations.ValidationResult;

namespace S7.Core.Abstractions.Configuration
{
    /// <summary>
    /// Base class for all configuration options with validation support.
    /// </summary>
    public abstract class ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets whether this configuration section is enabled.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the configuration version for compatibility checking.
        /// </summary>
        public string Version { get; set; } = "1.0";

        /// <summary>
        /// Validates the configuration options.
        /// </summary>
        /// <returns>True if valid, false otherwise.</returns>
        public virtual bool IsValid()
        {
            var context = new ValidationContext(this);
            var results = new List<ValidationResult>();
            return Validator.TryValidateObject(this, context, results, true);
        }

        /// <summary>
        /// Gets validation errors for the configuration options.
        /// </summary>
        /// <returns>Collection of validation results.</returns>
        public virtual IEnumerable<ValidationResult> GetValidationErrors()
        {
            var context = new ValidationContext(this);
            var results = new List<ValidationResult>();
            Validator.TryValidateObject(this, context, results, true);
            return results;
        }
    }

    /// <summary>
    /// Configuration options for PLC operations.
    /// </summary>
    public class PlcOperationOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the default connection timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 1000, MaxTimeoutMs = 60000)]
        public int ConnectionTimeoutMs { get; set; } = 10000;

        /// <summary>
        /// Gets or sets the default operation timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 500, MaxTimeoutMs = 30000)]
        public int OperationTimeoutMs { get; set; } = 5000;

        /// <summary>
        /// Gets or sets the maximum retry attempts for failed operations.
        /// </summary>
        [Range(0, 10)]
        public int MaxRetryAttempts { get; set; } = 3;

        /// <summary>
        /// Gets or sets the delay between retry attempts in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 100, MaxTimeoutMs = 10000)]
        public int RetryDelayMs { get; set; } = 1000;

        /// <summary>
        /// Gets or sets whether to validate checksums during memory operations.
        /// </summary>
        public bool ValidateChecksums { get; set; } = true;

        /// <summary>
        /// Gets or sets the default memory page size for operations.
        /// </summary>
        [NumericRange(256, 65536, Alignment = 256)]
        public int DefaultPageSize { get; set; } = 4096;
    }

    /// <summary>
    /// Configuration options for memory dump operations.
    /// </summary>
    public class MemoryDumpOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the default start address for memory dumps.
        /// </summary>
        [HexAddress(MinValue = 0x0, MaxValue = 0xFFFFFFFF)]
        public string DefaultStartAddress { get; set; } = "0x0";

        /// <summary>
        /// Gets or sets the default dump size in bytes.
        /// </summary>
        [NumericRange(1, 0x10000000, Alignment = 4)] // Max 256MB, 4-byte aligned
        public long DefaultDumpSize { get; set; } = 0x100000; // 1MB

        /// <summary>
        /// Gets or sets the default output directory for memory dumps.
        /// </summary>
        [FilePath(MustExist = false, AllowDirectories = true)]
        public string DefaultOutputDirectory { get; set; } = "./dumps";

        /// <summary>
        /// Gets or sets whether to compress dump files.
        /// </summary>
        public bool CompressDumps { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to generate checksums for dump files.
        /// </summary>
        public bool GenerateChecksums { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum number of concurrent dump operations.
        /// </summary>
        [Range(1, 10)]
        public int MaxConcurrentDumps { get; set; } = 2;
    }

    /// <summary>
    /// Configuration options for stager operations.
    /// </summary>
    public class StagerOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the default stager installation address.
        /// </summary>
        [HexAddress(MinValue = 0x1000, MaxValue = 0xFFFFFFFF)]
        public string DefaultInstallAddress { get; set; } = "0x10000";

        /// <summary>
        /// Gets or sets the stager binary file path.
        /// </summary>
        [FilePath(AllowedExtensions = new[] { "bin", "hex", "elf" })]
        public string StagerBinaryPath { get; set; } = "./Resources/stager.bin";

        /// <summary>
        /// Gets or sets whether to verify stager installation.
        /// </summary>
        public bool VerifyInstallation { get; set; } = true;

        /// <summary>
        /// Gets or sets the verification timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 1000, MaxTimeoutMs = 30000)]
        public int VerificationTimeoutMs { get; set; } = 5000;

        /// <summary>
        /// Gets or sets whether to perform power cycling during installation.
        /// </summary>
        public bool EnablePowerCycling { get; set; } = true;

        /// <summary>
        /// Gets or sets the power cycle delay in seconds.
        /// </summary>
        [Range(1, 60)]
        public int PowerCycleDelaySeconds { get; set; } = 3;
    }

    /// <summary>
    /// Configuration options for payload operations.
    /// </summary>
    public class PayloadOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the payload scan directories.
        /// </summary>
        [Required]
        public string[] ScanDirectories { get; set; } = new[] { "./Resources/payloads" };

        /// <summary>
        /// Gets or sets the allowed payload file extensions.
        /// </summary>
        public string[] AllowedExtensions { get; set; } = new[] { "bin", "hex", "elf", "c", "s" };

        /// <summary>
        /// Gets or sets whether to enable payload caching.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache expiration time in minutes.
        /// </summary>
        [Range(1, 1440)] // 1 minute to 24 hours
        public int CacheExpirationMinutes { get; set; } = 60;

        /// <summary>
        /// Gets or sets whether to automatically compile source payloads.
        /// </summary>
        public bool AutoCompile { get; set; } = true;

        /// <summary>
        /// Gets or sets the compiler timeout in seconds.
        /// </summary>
        [Range(10, 300)] // 10 seconds to 5 minutes
        public int CompilerTimeoutSeconds { get; set; } = 60;
    }

    /// <summary>
    /// Configuration options for communication channels.
    /// </summary>
    public class CommunicationChannelOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the default socat binary path.
        /// </summary>
        [FilePath(AllowEmpty = true)]
        public string SocatBinaryPath { get; set; } = "/usr/bin/socat";

        /// <summary>
        /// Gets or sets the default serial port configuration.
        /// </summary>
        public SerialPortConfiguration DefaultSerialPort { get; set; } = new();

        /// <summary>
        /// Gets or sets the channel connection timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 1000, MaxTimeoutMs = 30000)]
        public int ConnectionTimeoutMs { get; set; } = 10000;

        /// <summary>
        /// Gets or sets whether to automatically discover serial ports.
        /// </summary>
        public bool AutoDiscoverPorts { get; set; } = true;

        /// <summary>
        /// Gets or sets the port discovery interval in seconds.
        /// </summary>
        [Range(5, 300)] // 5 seconds to 5 minutes
        public int DiscoveryIntervalSeconds { get; set; } = 30;
    }

    /// <summary>
    /// Configuration for serial port settings.
    /// </summary>
    public class SerialPortConfiguration
    {
        /// <summary>
        /// Gets or sets the default baud rate.
        /// </summary>
        [Range(300, 921600)]
        public int BaudRate { get; set; } = 115200;

        /// <summary>
        /// Gets or sets the data bits.
        /// </summary>
        [Range(5, 8)]
        public int DataBits { get; set; } = 8;

        /// <summary>
        /// Gets or sets the stop bits.
        /// </summary>
        [Range(1, 2)]
        public int StopBits { get; set; } = 1;

        /// <summary>
        /// Gets or sets the parity setting.
        /// </summary>
        [RegularExpression("^(None|Odd|Even|Mark|Space)$")]
        public string Parity { get; set; } = "None";

        /// <summary>
        /// Gets or sets the flow control setting.
        /// </summary>
        [RegularExpression("^(None|Hardware|Software)$")]
        public string FlowControl { get; set; } = "None";
    }

    /// <summary>
    /// Configuration options for power supply operations.
    /// </summary>
    public class PowerSupplyOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the default Modbus host.
        /// </summary>
        [NetworkEndpoint]
        public string DefaultHost { get; set; } = "localhost:502";

        /// <summary>
        /// Gets or sets the default slave ID.
        /// </summary>
        [Range(0, 255)]
        public byte DefaultSlaveId { get; set; } = 1;

        /// <summary>
        /// Gets or sets the default coil address.
        /// </summary>
        [Range(1, 65535)]
        public ushort DefaultCoilAddress { get; set; } = 1;

        /// <summary>
        /// Gets or sets the connection timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 1000, MaxTimeoutMs = 30000)]
        public int ConnectionTimeoutMs { get; set; } = 10000;

        /// <summary>
        /// Gets or sets the operation timeout in milliseconds.
        /// </summary>
        [Timeout(MinTimeoutMs = 500, MaxTimeoutMs = 10000)]
        public int OperationTimeoutMs { get; set; } = 5000;

        /// <summary>
        /// Gets or sets the default power cycle delay in seconds.
        /// </summary>
        [Range(1, 60)]
        public int DefaultPowerCycleDelaySeconds { get; set; } = 3;
    }

    /// <summary>
    /// Configuration options for logging.
    /// </summary>
    public class LoggingOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the minimum log level.
        /// </summary>
        [RegularExpression("^(Trace|Debug|Information|Warning|Error|Critical)$")]
        public string MinimumLevel { get; set; } = "Information";

        /// <summary>
        /// Gets or sets the log file path.
        /// </summary>
        [FilePath(MustExist = false, AllowEmpty = true)]
        public string LogFilePath { get; set; } = "./logs/application.log";

        /// <summary>
        /// Gets or sets whether to enable console logging.
        /// </summary>
        public bool EnableConsoleLogging { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to enable file logging.
        /// </summary>
        public bool EnableFileLogging { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum log file size in MB.
        /// </summary>
        [Range(1, 1000)]
        public int MaxFileSizeMB { get; set; } = 100;

        /// <summary>
        /// Gets or sets the number of log files to retain.
        /// </summary>
        [Range(1, 50)]
        public int RetainedFileCount { get; set; } = 10;
    }

    /// <summary>
    /// Root application configuration options.
    /// </summary>
    public class ApplicationOptions : ConfigurationOptionsBase
    {
        /// <summary>
        /// Gets or sets the PLC operation options.
        /// </summary>
        public PlcOperationOptions PlcOperations { get; set; } = new();

        /// <summary>
        /// Gets or sets the memory dump options.
        /// </summary>
        public MemoryDumpOptions MemoryDump { get; set; } = new();

        /// <summary>
        /// Gets or sets the stager options.
        /// </summary>
        public StagerOptions Stager { get; set; } = new();

        /// <summary>
        /// Gets or sets the payload options.
        /// </summary>
        public PayloadOptions Payload { get; set; } = new();

        /// <summary>
        /// Gets or sets the communication channel options.
        /// </summary>
        public CommunicationChannelOptions CommunicationChannel { get; set; } = new();

        /// <summary>
        /// Gets or sets the power supply options.
        /// </summary>
        public PowerSupplyOptions PowerSupply { get; set; } = new();

        /// <summary>
        /// Gets or sets the logging options.
        /// </summary>
        public LoggingOptions Logging { get; set; } = new();

        /// <summary>
        /// Validates all configuration sections.
        /// </summary>
        /// <returns>True if all sections are valid, false otherwise.</returns>
        public override bool IsValid()
        {
            return base.IsValid() &&
                   PlcOperations.IsValid() &&
                   MemoryDump.IsValid() &&
                   Stager.IsValid() &&
                   Payload.IsValid() &&
                   CommunicationChannel.IsValid() &&
                   PowerSupply.IsValid() &&
                   Logging.IsValid();
        }

        /// <summary>
        /// Gets validation errors for all configuration sections.
        /// </summary>
        /// <returns>Collection of validation results from all sections.</returns>
        public override IEnumerable<ValidationResult> GetValidationErrors()
        {
            var errors = new List<ValidationResult>();
            
            errors.AddRange(base.GetValidationErrors());
            errors.AddRange(PlcOperations.GetValidationErrors());
            errors.AddRange(MemoryDump.GetValidationErrors());
            errors.AddRange(Stager.GetValidationErrors());
            errors.AddRange(Payload.GetValidationErrors());
            errors.AddRange(CommunicationChannel.GetValidationErrors());
            errors.AddRange(PowerSupply.GetValidationErrors());
            errors.AddRange(Logging.GetValidationErrors());

            return errors;
        }
    }
}