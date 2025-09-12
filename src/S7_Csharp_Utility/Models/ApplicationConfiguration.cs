using System.IO.Ports;

namespace S7_Csharp_Utility.Models
{
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
        public string SelectedSerialPort { get; set; } = string.Empty;
        public int SocatTcpPort { get; set; } = 8888;
        public int SelectedBaudRate { get; set; } = 115200;
        public Parity SelectedParity { get; set; } = Parity.None;
        public StopBits SelectedStopBits { get; set; } = StopBits.One;
        public Handshake SelectedFlowControl { get; set; } = Handshake.None;
    }
}
