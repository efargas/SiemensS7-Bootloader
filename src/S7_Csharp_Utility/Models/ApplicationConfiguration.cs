using System.IO.Ports;

namespace S7_Csharp_Utility.Models
{
    /// <summary>
    /// Represents the application's configuration as a plain data object.
    /// </summary>
    public class ApplicationConfiguration
    {
        public string PlcHost { get; set; } = "localhost";
        public int PlcPort { get; set; } = 102;
        public string ModbusHost { get; set; } = "localhost";
        public int ModbusPort { get; set; } = 502;
        public ushort ModbusCoil { get; set; } = 1;
        public int DelaySeconds { get; set; } = 1;
        public string DumpAddress { get; set; } = "0x10000000";
        public uint DumpLength { get; set; } = 4096;
        public string CompareFolder { get; set; } = string.Empty;
        public string CompareFile1 { get; set; } = string.Empty;
        public string CompareFile2 { get; set; } = string.Empty;
        public string? SelectedSerialPort { get; set; } = "/dev/ttyUSB0";
        public int SocatTcpPort { get; set; } = 1238;
        public int SelectedBaudRate { get; set; } = 38400;
        public Parity SelectedParity { get; set; } = Parity.Even;
        public StopBits SelectedStopBits { get; set; } = StopBits.One;
        public Handshake SelectedFlowControl { get; set; } = Handshake.None;
        public bool SocatVerbose { get; set; } = true;
        public bool SocatHexDump { get; set; } = true;
        public int SocatBlockSize { get; set; } = 4;
        public string PayloadsPath { get; set; } = string.Empty;
        public string DumpsPath { get; set; } = string.Empty;
        public string LogsPath { get; set; } = string.Empty;
        public string ExtractionPath { get; set; } = string.Empty;
    }
}