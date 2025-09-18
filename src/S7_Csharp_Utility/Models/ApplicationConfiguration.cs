using System.IO.Ports;
using System;
using System.IO;

namespace S7_Csharp_Utility.Models
{
    /// <summary>
    /// Represents the application's configuration.
    /// </summary>
    public class ApplicationConfiguration
    {
        /// <summary>
        /// The IP address or hostname of the PLC.
        /// </summary>
        public string PlcHost { get; set; } = "localhost";
        /// <summary>
        /// The TCP port of the PLC.
        /// </summary>
        public int PlcPort { get; set; } = 102;
        /// <summary>
        /// The IP address or hostname of the Modbus-enabled power supply.
        /// </summary>
        public string ModbusHost { get; set; } = "localhost";
        /// <summary>
        /// The TCP port of the Modbus-enabled power supply.
        /// </summary>
        public int ModbusPort { get; set; } = 502;
        /// <summary>
        /// The Modbus coil to control the power supply.
        /// </summary>
        public ushort ModbusCoil { get; set; } = 1;
        /// <summary>
        /// The delay in seconds to wait before powering on the PLC.
        /// </summary>
        public int DelaySeconds { get; set; } = 1;
        /// <summary>
        /// The starting memory address for the dump, in hexadecimal format.
        /// </summary>
        public string DumpAddress { get; set; } = "0x10000000";
        /// <summary>
        /// The number of bytes to dump from the memory address.
        /// </summary>
        public uint DumpLength { get; set; } = 4096;
        /// <summary>
        /// The folder containing dumps to be compared.
        /// </summary>
        public string CompareFolder { get; set; } = string.Empty;
        /// <summary>
        /// The first file to be compared.
        /// </summary>
        public string CompareFile1 { get; set; } = string.Empty;
        /// <summary>
        /// The second file to be compared.
        /// </summary>
        public string CompareFile2 { get; set; } = string.Empty;
        /// <summary>
        /// The currently selected serial port.
        /// </summary>
        public string SelectedSerialPort { get; set; } = "/dev/ttyUSB0";
        /// <summary>
        /// The TCP port used by socat.
        /// </summary>
        public int SocatTcpPort { get; set; } = 1238;
        /// <summary>
        /// The currently selected baud rate.
        /// </summary>
        public int SelectedBaudRate { get; set; } = 38400;
        /// <summary>
        /// The currently selected parity.
        /// </summary>
        public Parity SelectedParity { get; set; } = Parity.Even;
        /// <summary>
        /// The currently selected stop bits.
        /// </summary>
        public StopBits SelectedStopBits { get; set; } = StopBits.One;
        /// <summary>
        /// The currently selected flow control.
        /// </summary>
        public Handshake SelectedFlowControl { get; set; } = Handshake.None;
        /// <summary>
        /// Enables verbose output from socat (equivalent to -v).
        /// </summary>
        public bool SocatVerbose { get; set; } = true;
        /// <summary>
        /// Enables hexadecimal dump output from socat (equivalent to -x).
        /// </summary>
        public bool SocatHexDump { get; set; } = true;
        /// <summary>
        /// Sets the I/O block size for socat (equivalent to -b N).
        /// </summary>
        public int SocatBlockSize { get; set; } = 4;

        /// <summary>
        /// The path to the folder containing the stager payloads.
        /// </summary>
        public string PayloadsPath { get; set; } = GetPayloadsPath();

        /// <summary>
        /// The path to the folder where memory dumps will be saved.
        /// </summary>
        public string DumpsPath { get; set; } = GetDefaultDumpsPath();

        /// <summary>
        /// The path to the folder where logs will be saved.
        /// </summary>
        public string LogsPath { get; set; } = GetDefaultLogsPath();

        /// <summary>
        /// The path to the folder where extracted files will be saved.
        /// </summary>
        public string ExtractionPath { get; set; } = GetDefaultExtractionPath();

        /// <summary>
        /// Gets the fixed path for payloads folder (not user-configurable).
        /// This always points to the application's bundled payloads.
        /// </summary>
        public static string GetPayloadsPath()
        {
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "payloads"));
        }

        /// <summary>
        /// Gets the default path for dumps folder (user-configurable).
        /// Defaults to Resources/dumps but can be changed by user.
        /// </summary>
        public static string GetDefaultDumpsPath()
        {
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "dumps"));
        }

        /// <summary>
        /// Gets the default path for logs folder (user-configurable).
        /// Defaults to Resources/logs but can be changed by user.
        /// </summary>
        public static string GetDefaultLogsPath()
        {
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "logs"));
        }

        /// <summary>
        /// Gets the default path for extraction folder (user-configurable).
        /// Defaults to Resources/extracted but can be changed by user.
        /// </summary>
        public static string GetDefaultExtractionPath()
        {
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "extracted"));
        }

        /// <summary>
        /// Resolves a path, handling both absolute and relative paths correctly.
        /// If the path is relative, it's resolved relative to the application directory.
        /// If the path is absolute, it's returned as-is.
        /// If the path doesn't exist, it attempts to create the directory.
        /// </summary>
        /// <param name="configuredPath">The path from configuration</param>
        /// <param name="defaultPath">The default path to use if configuredPath is invalid</param>
        /// <returns>A valid, absolute path</returns>
        public static string ResolvePath(string configuredPath, string defaultPath)
        {
            try
            {
                // If configured path is null or empty, use default
                if (string.IsNullOrWhiteSpace(configuredPath))
                {
                    configuredPath = defaultPath;
                }

                // Convert to absolute path
                string absolutePath;
                if (Path.IsPathRooted(configuredPath))
                {
                    // Already absolute
                    absolutePath = Path.GetFullPath(configuredPath);
                }
                else
                {
                    // Relative to application directory
                    absolutePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredPath));
                }

                // Ensure directory exists
                if (!Directory.Exists(absolutePath))
                {
                    Directory.CreateDirectory(absolutePath);
                }

                return absolutePath;
            }
            catch (Exception)
            {
                // If anything fails, fall back to default and ensure it exists
                var fallbackPath = Path.GetFullPath(defaultPath);
                if (!Directory.Exists(fallbackPath))
                {
                    Directory.CreateDirectory(fallbackPath);
                }
                return fallbackPath;
            }
        }

        /// <summary>
        /// Creates a new ApplicationConfiguration with default values.
        /// </summary>
        public static ApplicationConfiguration CreateDefault()
        {
            return new ApplicationConfiguration
            {
                PlcHost = "localhost",
                PlcPort = 102,
                ModbusHost = "localhost",
                ModbusPort = 502,
                ModbusCoil = 1,
                DelaySeconds = 1,
                DumpAddress = "0x691E28",
                DumpLength = 16,
                CompareFolder = string.Empty,
                CompareFile1 = string.Empty,
                CompareFile2 = string.Empty,
                SelectedSerialPort = "/dev/ttyUSB0",
                SocatTcpPort = 1238,
                SelectedBaudRate = 38400,
                SelectedParity = Parity.Even,
                SelectedStopBits = StopBits.One,
                SelectedFlowControl = Handshake.None,
                SocatVerbose = true,
                SocatHexDump = true,
                SocatBlockSize = 4,
                PayloadsPath = GetPayloadsPath(),
                DumpsPath = GetDefaultDumpsPath(),
                LogsPath = GetDefaultLogsPath(),
                ExtractionPath = GetDefaultExtractionPath()
            };
        }
    }
}
