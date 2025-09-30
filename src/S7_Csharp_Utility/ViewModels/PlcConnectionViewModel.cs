#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.IO.Ports;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the PLC connection.
    /// </summary>
    public class PlcConnectionViewModel : ViewModelBase
    {
        private readonly SocatService _socatService;
        private readonly IDialogService _dialogService;
        private readonly ILogger<PlcConnectionViewModel> _logger;
        private readonly ISerialPortService _serialPortService;

        /// <summary>
        /// Occurs when the socat status changes.
        /// </summary>
        public event Action<string>? SocatStatusChanged;

        private string _plcHost = "localhost";
        [Required]
        public string PlcHost
        {
            get => _plcHost;
            set => SetProperty(ref _plcHost, value);
        }

        private int _plcPort = 102;
        [Range(1, 65535)]
        public int PlcPort
        {
            get => _plcPort;
            set => SetProperty(ref _plcPort, value);
        }

        public ObservableCollection<string> CommunicationModes { get; } = new ObservableCollection<string> { "TCP (socat)", "Serial" };
        private string? _selectedCommunicationMode = "TCP (socat)";
        public string? SelectedCommunicationMode
        {
            get => _selectedCommunicationMode;
            set => SetProperty(ref _selectedCommunicationMode, value);
        }

        public ObservableCollection<string> AvailableSerialPorts { get; } = new ObservableCollection<string>();
        private string? _selectedSerialPort = string.Empty;
        public string? SelectedSerialPort
        {
            get => _selectedSerialPort;
            set => SetProperty(ref _selectedSerialPort, value);
        }

        private int _socatTcpPort = 1238;
        public int SocatTcpPort
        {
            get => _socatTcpPort;
            set => SetProperty(ref _socatTcpPort, value);
        }

        private bool _socatVerbose = true;
        public bool SocatVerbose
        {
            get => _socatVerbose;
            set => SetProperty(ref _socatVerbose, value);
        }

        private bool _socatHexDump = true;
        public bool SocatHexDump
        {
            get => _socatHexDump;
            set => SetProperty(ref _socatHexDump, value);
        }

        private int _socatBlockSize = 4;
        public int SocatBlockSize
        {
            get => _socatBlockSize;
            set => SetProperty(ref _socatBlockSize, value);
        }

        private string _socatStatus = "Stopped";
        public string SocatStatus
        {
            get => _socatStatus;
            set
            {
                if (SetProperty(ref _socatStatus, value))
                {
                    ((AsyncRelayCommand)StartSocatCommand).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)StopSocatCommand).RaiseCanExecuteChanged();
                    SocatStatusChanged?.Invoke(value);
                }
            }
        }

        public ObservableCollection<int> AvailableBaudRates { get; } = new ObservableCollection<int> { 9600, 19200, 38400, 57600, 115200 };
        private int _selectedBaudRate = 38400;
        public int SelectedBaudRate
        {
            get => _selectedBaudRate;
            set => SetProperty(ref _selectedBaudRate, value);
        }

        public ObservableCollection<Parity> AvailableParities { get; } = new ObservableCollection<Parity>(Enum.GetValues(typeof(Parity)).Cast<Parity>());
        private Parity _selectedParity = Parity.Even;
        public Parity SelectedParity
        {
            get => _selectedParity;
            set => SetProperty(ref _selectedParity, value);
        }

        public ObservableCollection<StopBits> AvailableStopBits { get; } = new ObservableCollection<StopBits>(Enum.GetValues(typeof(StopBits)).Cast<StopBits>());
        private StopBits _selectedStopBits = StopBits.One;
        public StopBits SelectedStopBits
        {
            get => _selectedStopBits;
            set => SetProperty(ref _selectedStopBits, value);
        }

        public ObservableCollection<Handshake> AvailableFlowControls { get; } = new ObservableCollection<Handshake>(Enum.GetValues(typeof(Handshake)).Cast<Handshake>());
        private Handshake _selectedFlowControl = Handshake.None;
        public Handshake SelectedFlowControl
        {
            get => _selectedFlowControl;
            set => SetProperty(ref _selectedFlowControl, value);
        }

        public ICommand StartSocatCommand { get; }
        public ICommand StopSocatCommand { get; }
        public ICommand RefreshSerialPortsCommand { get; }
        public ICommand ShowSocatLogCommand { get; }
        public ICommand CheckSocatProcessesCommand { get; }
        public ICommand KillSocatProcessesCommand { get; }

        public PlcConnectionViewModel(
            SocatService socatService,
            IDialogService dialogService,
            ILogger<PlcConnectionViewModel> logger,
            ISerialPortService serialPortService)
        {
            _socatService = socatService ?? throw new ArgumentNullException(nameof(socatService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serialPortService = serialPortService ?? throw new ArgumentNullException(nameof(serialPortService));

            StartSocatCommand = new AsyncRelayCommand(StartSocatAsync, _ => SocatStatus != "Running", HandleException);
            StopSocatCommand = new AsyncRelayCommand(StopSocatAsync, _ => SocatStatus == "Running", HandleException);
            RefreshSerialPortsCommand = new AsyncRelayCommand(RefreshSerialPortsAsync, _ => true, HandleException);
            ShowSocatLogCommand = new RelayCommand(() => _dialogService.ShowSocatLogWindow());
            CheckSocatProcessesCommand = new AsyncRelayCommand(CheckSocatProcessesAsync, _ => true, HandleException);
            KillSocatProcessesCommand = new AsyncRelayCommand(KillSocatProcessesAsync, _ => true, HandleException);

            _ = RefreshSerialPortsAsync();
        }

        private async Task CheckSocatProcessesAsync()
        {
            var pids = await Task.Run(() => SocatService.GetSocatProcessIds());
            if (pids.Length == 0)
                _logger.LogInformation("No running socat instances detected.");
            else
                _logger.LogInformation("Socat running instances: {Pids}", string.Join(", ", pids));
        }

        private async Task KillSocatProcessesAsync()
        {
            await Task.Run(() => SocatService.KillAllSocatProcesses(message => _logger.LogInformation(message)));
            _logger.LogInformation("All socat processes terminated.");
        }

        private async Task RefreshSerialPortsAsync()
        {
            var ports = await _serialPortService.GetAvailablePortNamesAsync();
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                AvailableSerialPorts.Clear();
                foreach (var port in ports)
                {
                    AvailableSerialPorts.Add(port);
                }
                if (AvailableSerialPorts.Any() && string.IsNullOrEmpty(SelectedSerialPort))
                {
                    SelectedSerialPort = AvailableSerialPorts[0];
                }
            });
        }

        private async Task StartSocatAsync()
        {
            if (SelectedSerialPort == null)
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a serial port.");
                return;
            }
            SocatStatus = "Starting...";
            await Task.Run(() => _socatService.Start(SelectedSerialPort, SocatTcpPort, SocatVerbose, SocatHexDump, SocatBlockSize));
            SocatStatus = "Running";
        }

        private async Task StopSocatAsync()
        {
            SocatStatus = "Stopping...";
            await Task.Run(() => _socatService.Stop());
            SocatStatus = "Stopped";
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An error occurred in the PLC Connection view.");
            _dialogService.ShowMessageAsync("Error", ex.Message);
            if (SocatStatus != "Running")
            {
                SocatStatus = "Error";
            }
        }

        public void LoadFromAppConfig(ApplicationConfiguration config)
        {
            PlcHost = config.PlcHost ?? "localhost";
            PlcPort = config.PlcPort;
            SelectedSerialPort = config.SelectedSerialPort ?? string.Empty;
            SocatTcpPort = config.SocatTcpPort;
            SelectedBaudRate = config.SelectedBaudRate;
            SelectedParity = config.SelectedParity;
            SelectedStopBits = config.SelectedStopBits;
            SelectedFlowControl = config.SelectedFlowControl;
            SocatVerbose = config.SocatVerbose;
            SocatHexDump = config.SocatHexDump;
            SocatBlockSize = config.SocatBlockSize;
        }

        public void SaveToAppConfig(ApplicationConfiguration config)
        {
            config.PlcHost = PlcHost;
            config.PlcPort = PlcPort;
            config.SelectedSerialPort = SelectedSerialPort;
            config.SocatTcpPort = SocatTcpPort;
            config.SelectedBaudRate = SelectedBaudRate;
            config.SelectedParity = SelectedParity;
            config.SelectedStopBits = SelectedStopBits;
            config.SelectedFlowControl = SelectedFlowControl;
            config.SocatVerbose = SocatVerbose;
            config.SocatHexDump = SocatHexDump;
            config.SocatBlockSize = SocatBlockSize;
        }
    }
}