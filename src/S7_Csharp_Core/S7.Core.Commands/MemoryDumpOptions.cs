using System.ComponentModel.DataAnnotations;

namespace S7.Core.Commands
{
    /// <summary>
    /// Options for memory dump command execution.
    /// </summary>
    public class MemoryDumpOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the memory address to start dumping from.
        /// </summary>
        [Required(ErrorMessage = "Memory address is required")]
        [Range(0x10000000, 0x20000000, ErrorMessage = "Address must be within valid IRAM range (0x10000000 - 0x20000000)")]
        public uint Address { get; set; }

        /// <summary>
        /// Gets or sets the number of bytes to dump.
        /// </summary>
        [Range(1, 0x100000, ErrorMessage = "Length must be between 1 and 1MB (1048576 bytes)")]
        public uint Length { get; set; } = 16;

        /// <summary>
        /// Gets or sets the output directory path where the dump file will be saved.
        /// </summary>
        [Required(ErrorMessage = "Output path is required")]
        public string OutputPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the path to the memory dumper payload.
        /// </summary>
        [Required(ErrorMessage = "Payload path is required")]
        public string PayloadPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the communication channel configuration.
        /// </summary>
        [Required(ErrorMessage = "Communication channel configuration is required")]
        public CommunicationChannelConfig ChannelConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets a value indicating whether to overwrite existing dump files.
        /// </summary>
        public bool OverwriteExisting { get; set; } = false;

        /// <summary>
        /// Gets or sets the custom filename for the dump file (optional).
        /// If not provided, a default filename will be generated.
        /// </summary>
        public string? CustomFilename { get; set; }
    }

    /// <summary>
    /// Configuration for communication channel.
    /// </summary>
    public class CommunicationChannelConfig
    {
        /// <summary>
        /// Gets or sets the communication mode (TCP or Serial).
        /// </summary>
        [Required(ErrorMessage = "Communication mode is required")]
        public string Mode { get; set; } = "TCP";

        /// <summary>
        /// Gets or sets the host address for TCP communication.
        /// </summary>
        public string? Host { get; set; }

        /// <summary>
        /// Gets or sets the port for TCP communication.
        /// </summary>
        [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
        public int Port { get; set; } = 8888;

        /// <summary>
        /// Gets or sets the serial port name for serial communication.
        /// </summary>
        public string? SerialPort { get; set; }

        /// <summary>
        /// Gets or sets the baud rate for serial communication.
        /// </summary>
        public int BaudRate { get; set; } = 115200;

        /// <summary>
        /// Gets or sets the parity for serial communication.
        /// </summary>
        public string Parity { get; set; } = "None";

        /// <summary>
        /// Gets or sets the stop bits for serial communication.
        /// </summary>
        public string StopBits { get; set; } = "One";

        /// <summary>
        /// Gets or sets the flow control for serial communication.
        /// </summary>
        public string FlowControl { get; set; } = "None";
    }
}