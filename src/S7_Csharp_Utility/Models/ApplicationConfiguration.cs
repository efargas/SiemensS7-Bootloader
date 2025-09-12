using System.IO.Ports;

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
    }
}
