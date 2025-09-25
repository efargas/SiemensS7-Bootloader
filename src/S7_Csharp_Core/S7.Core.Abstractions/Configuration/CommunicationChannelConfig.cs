using System;
using System.ComponentModel.DataAnnotations;

namespace S7.Core.Abstractions.Configuration
{
    /// <summary>
    /// Configuration for communication channel settings.
    /// </summary>
    public class CommunicationChannelConfig
    {
        /// <summary>
        /// Gets or sets the communication mode (TCP or Serial).
        /// </summary>
        [Required]
        public string Mode { get; init; } = "TCP";

        /// <summary>
        /// Gets or sets the host address for TCP communication.
        /// </summary>
        public string? Host { get; init; }

        /// <summary>
        /// Gets or sets the port number for TCP communication.
        /// </summary>
        [Range(1, 65535)]
        public int Port { get; init; } = 102;

        /// <summary>
        /// Gets or sets the serial port name for serial communication.
        /// </summary>
        public string? SerialPort { get; init; }

        /// <summary>
        /// Gets or sets the baud rate for serial communication.
        /// </summary>
        [Range(300, 115200)]
        public int BaudRate { get; init; } = 9600;

        /// <summary>
        /// Gets or sets the parity setting for serial communication.
        /// </summary>
        public string Parity { get; init; } = "None";

        /// <summary>
        /// Gets or sets the stop bits setting for serial communication.
        /// </summary>
        public string StopBits { get; init; } = "One";

        /// <summary>
        /// Gets or sets the flow control setting for serial communication.
        /// </summary>
        public string FlowControl { get; init; } = "None";

        /// <summary>
        /// Gets or sets the connection timeout.
        /// </summary>
        public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    }
}