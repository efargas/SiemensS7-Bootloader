using System.ComponentModel;
using System.IO.Ports;
using System.Threading.Tasks;
using S7_Csharp_Utility.Models;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines the contract for a service that manages the application's shared state.
    /// </summary>
    public interface IApplicationStateService : INotifyPropertyChanged
    {
        // State Properties
        string SelectedCommunicationMode { get; set; }
        string PlcHost { get; set; }
        int PlcPort { get; set; }
        string ModbusHost { get; set; }
        int ModbusPort { get; set; }
        ushort ModbusCoil { get; set; }
        byte ModbusSlaveId { get; set; }
        int DelaySeconds { get; set; }
        string SocatStatus { get; set; }
        string ModbusStatus { get; set; }
        bool IsSocatRunning { get; }
        bool IsModbusConnected { get; }
        string DumpAddress { get; set; }
        uint DumpLength { get; set; }
        string CompareFolder { get; set; }
        string CompareFile1 { get; set; }
        string CompareFile2 { get; set; }
        string? SelectedSerialPort { get; set; }
        int SocatTcpPort { get; set; }
        int SelectedBaudRate { get; set; }
        Parity SelectedParity { get; set; }
        StopBits SelectedStopBits { get; set; }
        Handshake SelectedFlowControl { get; set; }
        bool SocatVerbose { get; set; }
        bool SocatHexDump { get; set; }
        int SocatBlockSize { get; set; }
        string PayloadsPath { get; set; }
        string DumpsPath { get; set; }
        string LogsPath { get; set; }
        string ExtractionPath { get; set; }
        DeviceProfile? LoadedProfile { get; set; }
        bool IsAnyOperationInProgress { get; }

        // Configuration Methods
        Task LoadConfigurationOnStartup();
        Task LoadConfigurationAsync();
        Task SaveConfigurationAsync();
        Task SaveConfigurationOnExit();
        Task LoadProfileAsync();

        // Operation State Methods
        void NotifyOperationStarted(string operationName);
        void NotifyOperationCompleted(string operationName);
        S7.Core.Abstractions.Configuration.CommunicationChannelConfig CreateChannelConfig();
        bool CanExecuteMemoryDump { get; }
    }
}