using System.ComponentModel.DataAnnotations;

namespace S7.Core.Commands
{
    /// <summary>
    /// Options for stager installation command execution.
    /// </summary>
    public class StagerInstallOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the path to the stager payload.
        /// </summary>
        [Required(ErrorMessage = "Payload path is required")]
        public string PayloadPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the communication channel configuration.
        /// </summary>
        [Required(ErrorMessage = "Communication channel configuration is required")]
        public CommunicationChannelConfig ChannelConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets the power cycle configuration.
        /// </summary>
        [Required(ErrorMessage = "Power cycle configuration is required")]
        public PowerCycleConfig PowerConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets the timeout for the stager installation in milliseconds.
        /// </summary>
        [Range(1000, 60000, ErrorMessage = "Timeout must be between 1 and 60 seconds")]
        public int TimeoutMs { get; set; } = 30000;

        /// <summary>
        /// Gets or sets a value indicating whether to perform a handshake before installation.
        /// </summary>
        public bool PerformHandshake { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to get version information after connection.
        /// </summary>
        public bool GetVersionInfo { get; set; } = true;
    }

    /// <summary>
    /// Configuration for power cycling operations.
    /// </summary>
    public class PowerCycleConfig
    {
        /// <summary>
        /// Gets or sets the Modbus host address.
        /// </summary>
        [Required(ErrorMessage = "Modbus host is required")]
        public string Host { get; set; } = "localhost";

        /// <summary>
        /// Gets or sets the Modbus port.
        /// </summary>
        [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
        public int Port { get; set; } = 502;

        /// <summary>
        /// Gets or sets the Modbus coil address.
        /// </summary>
        [Range(0, 65535, ErrorMessage = "Coil must be between 0 and 65535")]
        public int Coil { get; set; } = 0;

        /// <summary>
        /// Gets or sets the delay in seconds after power cycling.
        /// </summary>
        [Range(1, 60, ErrorMessage = "Delay must be between 1 and 60 seconds")]
        public int DelaySeconds { get; set; } = 5;
    }
}