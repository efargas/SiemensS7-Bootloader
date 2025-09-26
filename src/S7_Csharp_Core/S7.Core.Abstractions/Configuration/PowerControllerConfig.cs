using System;
using System.ComponentModel.DataAnnotations;

namespace S7.Core.Abstractions.Configuration
{
    /// <summary>
    /// Configuration for power controller settings.
    /// </summary>
    public class PowerControllerConfig
    {
        /// <summary>
        /// Gets or sets the Modbus host address.
        /// </summary>
        [Required]
        public string Host { get; init; } = string.Empty;

        /// <summary>
        /// Gets or sets the Modbus port number.
        /// </summary>
        [Range(1, 65535)]
        public int Port { get; init; } = 502;

        /// <summary>
        /// Gets or sets the coil address for power control.
        /// </summary>
        [Range(0, 65535)]
        public int Coil { get; init; }

        /// <summary>
        /// Gets or sets the coil address for power control (ushort version for compatibility).
        /// </summary>
        public ushort CoilAddress => (ushort)Coil;

        /// <summary>
        /// Gets or sets the Modbus slave ID.
        /// </summary>
        [Range(1, 255)]
        public byte SlaveId { get; init; } = 1;

        /// <summary>
        /// Gets or sets the delay in seconds after power cycle.
        /// </summary>
        [Range(0, 300)]
        public int DelaySeconds { get; init; } = 5;

        /// <summary>
        /// Gets or sets the delay in milliseconds when power is turned OFF during power cycle.
        /// </summary>
        [Range(100, 60000)]
        public int OffDelayMs { get; init; } = 2000;

        /// <summary>
        /// Gets or sets the delay in milliseconds when power is turned ON during power cycle.
        /// </summary>
        [Range(100, 60000)]
        public int OnDelayMs { get; init; } = 3000;

        /// <summary>
        /// Gets or sets the operation timeout.
        /// </summary>
        public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the number of retry attempts.
        /// </summary>
        [Range(0, 10)]
        public int RetryAttempts { get; init; } = 3;

        /// <summary>
        /// Gets or sets the delay between retry attempts.
        /// </summary>
        public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1);
    }
}