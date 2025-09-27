using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.ViewModels;
using System.IO.Ports;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Manages the application's shared state and notifies the UI of any changes.
    /// </summary>
    public class ApplicationStateService : ViewModelBase, IApplicationStateService
    {
        private const string ConfigFileName = "config.json";
        private readonly ConfigurationService _configService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly SocatLoggerService _socatLoggerService;
        private readonly ILogger<ApplicationStateService> _logger;
        private readonly List<string> _activeOperations = new List<string>();

        public ApplicationStateService(
            ConfigurationService configService,
            IDialogService dialogService,
            LoggingService loggingService,
            SocatLoggerService socatLoggerService,
            ILogger<ApplicationStateService> logger)
        {
            _configService = configService;
            _dialogService = dialogService;
            _loggingService = loggingService;
            _socatLoggerService = socatLoggerService;
            _logger = logger;
        }

        private string _selectedCommunicationMode = "TCP (socat)";
        public string SelectedCommunicationMode { get => _selectedCommunicationMode; set => SetProperty(ref _selectedCommunicationMode, value); }

        private string _plcHost = "localhost";
        public string PlcHost { get => _plcHost; set => SetProperty(ref _plcHost, value); }

        private int _plcPort = 102;
        public int PlcPort { get => _plcPort; set => SetProperty(ref _plcPort, value); }

        private string _modbusHost = "localhost";
        public string ModbusHost { get => _modbusHost; set => SetProperty(ref _modbusHost, value); }

        private int _modbusPort = 502;
        public int ModbusPort { get => _modbusPort; set => SetProperty(ref _modbusPort, value); }

        private ushort _modbusCoil = 1;
        public ushort ModbusCoil { get => _modbusCoil; set => SetProperty(ref _modbusCoil, value); }

        private byte _modbusSlaveId = 1;
        public byte ModbusSlaveId { get => _modbusSlaveId; set => SetProperty(ref _modbusSlaveId, value); }

        private int _delaySeconds = 1;
        public int DelaySeconds { get => _delaySeconds; set => SetProperty(ref _delaySeconds, value); }

        private string _dumpAddress = "0x10000000";
        public string DumpAddress { get => _dumpAddress; set => SetProperty(ref _dumpAddress, value); }

        private uint _dumpLength = 4096;
        public uint DumpLength { get => _dumpLength; set => SetProperty(ref _dumpLength, value); }

        private string _compareFolder = string.Empty;
        public string CompareFolder { get => _compareFolder; set => SetProperty(ref _compareFolder, value); }

        private string _compareFile1 = string.Empty;
        public string CompareFile1 { get => _compareFile1; set => SetProperty(ref _compareFile1, value); }

        private string _compareFile2 = string.Empty;
        public string CompareFile2 { get => _compareFile2; set => SetProperty(ref _compareFile2, value); }

        private string? _selectedSerialPort = "/dev/ttyUSB0";
        public string? SelectedSerialPort { get => _selectedSerialPort; set => SetProperty(ref _selectedSerialPort, value); }

        private int _socatTcpPort = 1238;
        public int SocatTcpPort { get => _socatTcpPort; set => SetProperty(ref _socatTcpPort, value); }

        private int _selectedBaudRate = 38400;
        public int SelectedBaudRate { get => _selectedBaudRate; set => SetProperty(ref _selectedBaudRate, value); }

        private Parity _selectedParity = Parity.Even;
        public Parity SelectedParity { get => _selectedParity; set => SetProperty(ref _selectedParity, value); }

        private StopBits _selectedStopBits = StopBits.One;
        public StopBits SelectedStopBits { get => _selectedStopBits; set => SetProperty(ref _selectedStopBits, value); }

        private Handshake _selectedFlowControl = Handshake.None;
        public Handshake SelectedFlowControl { get => _selectedFlowControl; set => SetProperty(ref _selectedFlowControl, value); }

        private bool _socatVerbose = true;
        public bool SocatVerbose { get => _socatVerbose; set => SetProperty(ref _socatVerbose, value); }

        private bool _socatHexDump = true;
        public bool SocatHexDump { get => _socatHexDump; set => SetProperty(ref _socatHexDump, value); }

        private int _socatBlockSize = 4;
        public int SocatBlockSize { get => _socatBlockSize; set => SetProperty(ref _socatBlockSize, value); }

        private string _payloadsPath = ApplicationConfiguration.GetPayloadsPath();
        public string PayloadsPath { get => _payloadsPath; set => SetProperty(ref _payloadsPath, value); }

        private string _dumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();
        public string DumpsPath { get => _dumpsPath; set => SetProperty(ref _dumpsPath, value); }

        private string _logsPath = ApplicationConfiguration.GetDefaultLogsPath();
        public string LogsPath { get => _logsPath; set => SetProperty(ref _logsPath, value); }

        private string _extractionPath = ApplicationConfiguration.GetDefaultExtractionPath();
        public string ExtractionPath { get => _extractionPath; set => SetProperty(ref _extractionPath, value); }

        private string _socatStatus = "Stopped";
        public string SocatStatus { get => _socatStatus; set { if (SetProperty(ref _socatStatus, value)) OnPropertyChanged(nameof(IsSocatRunning)); } }

        private string _modbusStatus = "Disconnected";
        public string ModbusStatus { get => _modbusStatus; set { if (SetProperty(ref _modbusStatus, value)) OnPropertyChanged(nameof(IsModbusConnected)); } }

        public bool IsSocatRunning => SocatStatus == "Running";
        public bool IsModbusConnected => ModbusStatus == "Connected";

        private DeviceProfile? _loadedProfile;
        public DeviceProfile? LoadedProfile { get => _loadedProfile; set => SetProperty(ref _loadedProfile, value); }

        public bool IsAnyOperationInProgress => _activeOperations.Any();

        public bool CanExecuteMemoryDump => IsSocatRunning && !IsAnyOperationInProgress;

        public S7.Core.Abstractions.Configuration.CommunicationChannelConfig CreateChannelConfig()
        {
            if (SelectedCommunicationMode == "TCP (socat)")
            {
                return new S7.Core.Abstractions.Configuration.CommunicationChannelConfig
                {
                    Mode = "TCP",
                    Host = PlcHost,
                    Port = PlcPort,
                    Timeout = TimeSpan.FromSeconds(30)
                };
            }
            else if (SelectedCommunicationMode == "Serial" && !string.IsNullOrEmpty(SelectedSerialPort))
            {
                return new S7.Core.Abstractions.Configuration.CommunicationChannelConfig
                {
                    Mode = "Serial",
                    SerialPort = SelectedSerialPort,
                    BaudRate = SelectedBaudRate,
                    Parity = SelectedParity.ToString(),
                    StopBits = SelectedStopBits.ToString(),
                    FlowControl = SelectedFlowControl.ToString(),
                    Timeout = TimeSpan.FromSeconds(30)
                };
            }

            throw new InvalidOperationException("No valid communication channel configuration available");
        }

        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = await _configService.LoadConfigurationAsync(path);
                if (config != null)
                {
                    ApplyConfiguration(config);
                }
                else
                {
                    await SaveConfigurationOnExit();
                    _loggingService.Log($"No configuration found. Created default configuration at {path}.", LogCategory.Info);
                }
            }
            catch (Exception ex)
            {
                _loggingService.Log($"Could not load or create configuration: {ex.ToString()}", LogCategory.Warning);
            }
            UpdateLogsPath();
        }

        public async Task LoadConfigurationAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Configuration Files").ConfigureAwait(false);
            if (path != null)
            {
                try
                {
                    var config = await _configService.LoadConfigurationAsync(path);
                    if (config != null)
                    {
                        ApplyConfiguration(config);
                        UpdateLogsPath();
                        _loggingService.Log($"Configuration loaded successfully from {path}.", LogCategory.Info);
                        await _dialogService.ShowMessageAsync("Success", "Configuration loaded successfully!");
                    }
                    else
                    {
                        await _dialogService.ShowMessageAsync("Error", "Failed to load configuration file. The file may be corrupted or in an invalid format.");
                    }
                }
                catch (Exception ex)
                {
                    _loggingService.Log($"Error loading configuration from {path}: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Error loading configuration: {ex.Message}");
                }
            }
        }

        public async Task SaveConfigurationAsync()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Configuration Files").ConfigureAwait(false);
            if (path != null)
            {
                try
                {
                    var config = CreateConfiguration();
                    await _configService.SaveConfigurationAsync(config, path);
                    _loggingService.Log($"Configuration saved successfully to {path}.", LogCategory.Info);
                    await _dialogService.ShowMessageAsync("Success", "Configuration saved successfully!");
                }
                catch (Exception ex)
                {
                    _loggingService.Log($"Error saving configuration to {path}: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Error saving configuration: {ex.Message}");
                }
            }
        }

        public async Task SaveConfigurationOnExit()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = CreateConfiguration();
                await _configService.SaveConfigurationAsync(config, path);
            }
            catch (Exception ex)
            {
                _loggingService.Log($"Could not save configuration: {ex.ToString()}", LogCategory.Error);
            }
        }

        public async Task LoadProfileAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles").ConfigureAwait(false);
            if (path != null)
            {
                var profile = await _configService.LoadProfileAsync(path).ConfigureAwait(false);
                if (profile != null)
                {
                    LoadedProfile = profile;
                }
            }
        }

        public void NotifyOperationStarted(string operationName)
        {
            if (!_activeOperations.Contains(operationName))
            {
                _activeOperations.Add(operationName);
                OnPropertyChanged(nameof(IsAnyOperationInProgress));
            }
        }

        public void NotifyOperationCompleted(string operationName)
        {
            if (_activeOperations.Remove(operationName))
            {
                OnPropertyChanged(nameof(IsAnyOperationInProgress));
            }
        }

        private void ApplyConfiguration(ApplicationConfiguration config)
        {
            PlcHost = config.PlcHost ?? "localhost";
            PlcPort = config.PlcPort;
            ModbusHost = config.ModbusHost ?? "localhost";
            ModbusPort = config.ModbusPort;
            ModbusCoil = config.ModbusCoil;
            DelaySeconds = config.DelaySeconds;
            DumpAddress = config.DumpAddress ?? "0x691E28";
            DumpLength = config.DumpLength;
            CompareFolder = config.CompareFolder ?? string.Empty;
            CompareFile1 = config.CompareFile1 ?? string.Empty;
            CompareFile2 = config.CompareFile2 ?? string.Empty;
            SelectedSerialPort = config.SelectedSerialPort ?? string.Empty;
            SocatTcpPort = config.SocatTcpPort;
            SelectedBaudRate = config.SelectedBaudRate;
            SelectedParity = config.SelectedParity;
            SelectedStopBits = config.SelectedStopBits;
            SelectedFlowControl = config.SelectedFlowControl;
            SocatVerbose = config.SocatVerbose;
            SocatHexDump = config.SocatHexDump;
            SocatBlockSize = config.SocatBlockSize;
            PayloadsPath = config.PayloadsPath ?? ApplicationConfiguration.GetPayloadsPath();
            DumpsPath = config.DumpsPath ?? ApplicationConfiguration.GetDefaultDumpsPath();
            LogsPath = config.LogsPath ?? ApplicationConfiguration.GetDefaultLogsPath();
            ExtractionPath = config.ExtractionPath ?? ApplicationConfiguration.GetDefaultExtractionPath();
        }

        private ApplicationConfiguration CreateConfiguration()
        {
            return new ApplicationConfiguration
            {
                PlcHost = PlcHost,
                PlcPort = PlcPort,
                ModbusHost = ModbusHost,
                ModbusPort = ModbusPort,
                ModbusCoil = ModbusCoil,
                DelaySeconds = DelaySeconds,
                DumpAddress = DumpAddress,
                DumpLength = DumpLength,
                CompareFolder = CompareFolder,
                CompareFile1 = CompareFile1,
                CompareFile2 = CompareFile2,
                SelectedSerialPort = SelectedSerialPort,
                SocatTcpPort = SocatTcpPort,
                SelectedBaudRate = SelectedBaudRate,
                SelectedParity = SelectedParity,
                SelectedStopBits = SelectedStopBits,
                SelectedFlowControl = SelectedFlowControl,
                SocatVerbose = SocatVerbose,
                SocatHexDump = SocatHexDump,
                SocatBlockSize = SocatBlockSize,
                PayloadsPath = PayloadsPath,
                DumpsPath = DumpsPath,
                LogsPath = LogsPath,
                ExtractionPath = ExtractionPath
            };
        }

        private void UpdateLogsPath()
        {
            string resolvedLogsPath = ApplicationConfiguration.ResolvePath(LogsPath, ApplicationConfiguration.GetDefaultLogsPath());
            _loggingService.UpdateLogsPath(resolvedLogsPath);
            _socatLoggerService.UpdateLogsPath(resolvedLogsPath);
        }
    }
}