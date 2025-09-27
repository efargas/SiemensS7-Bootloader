#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7.Core.Abstractions.Services;
using Microsoft.Extensions.Logging;
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
        private readonly IApplicationStateService _state;
        private readonly ICommunicationChannelService _communicationChannelService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly ILogger<PlcConnectionViewModel> _logger;

        /// <summary>
        /// Occurs when the socat status changes.
        /// </summary>
        public event Action<string>? SocatStatusChanged;

        [Required]
        public string PlcHost { get => _state.PlcHost; set => _state.PlcHost = value; }

        [Range(1, 65535)]
        public int PlcPort { get => _state.PlcPort; set => _state.PlcPort = value; }

        public ObservableCollection<string> CommunicationModes { get; } = new ObservableCollection<string> { "TCP (socat)", "Serial" };

        public string? SelectedCommunicationMode { get => _state.SelectedCommunicationMode; set => _state.SelectedCommunicationMode = value; }

        public ObservableCollection<string> AvailableSerialPorts { get; } = new ObservableCollection<string>();

        public string? SelectedSerialPort { get => _state.SelectedSerialPort; set => _state.SelectedSerialPort = value; }

        public int SocatTcpPort { get => _state.SocatTcpPort; set => _state.SocatTcpPort = value; }

        public bool SocatVerbose { get => _state.SocatVerbose; set => _state.SocatVerbose = value; }

        public bool SocatHexDump { get => _state.SocatHexDump; set => _state.SocatHexDump = value; }

        public int SocatBlockSize { get => _state.SocatBlockSize; set => _state.SocatBlockSize = value; }

        private string _socatStatus = "Stopped";
        public string SocatStatus
        {
            get => _state.SocatStatus;
            set
            {
                if (_state.SocatStatus != value)
                {
                    _state.SocatStatus = value;
                    OnPropertyChanged(); // Notify local listeners
                    ((AsyncRelayCommand)StartSocatCommand).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)StopSocatCommand).RaiseCanExecuteChanged();
                    SocatStatusChanged?.Invoke(value);
                }
            }
        }

        public ObservableCollection<int> AvailableBaudRates { get; } = new ObservableCollection<int> { 9600, 19200, 38400, 57600, 115200 };

        public int SelectedBaudRate { get => _state.SelectedBaudRate; set => _state.SelectedBaudRate = value; }

        public ObservableCollection<Parity> AvailableParities { get; } = new ObservableCollection<Parity>(Enum.GetValues(typeof(Parity)).Cast<Parity>());

        public Parity SelectedParity { get => _state.SelectedParity; set => _state.SelectedParity = value; }

        public ObservableCollection<StopBits> AvailableStopBits { get; } = new ObservableCollection<StopBits>(Enum.GetValues(typeof(StopBits)).Cast<StopBits>());

        public StopBits SelectedStopBits { get => _state.SelectedStopBits; set => _state.SelectedStopBits = value; }

        public ObservableCollection<Handshake> AvailableFlowControls { get; } = new ObservableCollection<Handshake>(Enum.GetValues(typeof(Handshake)).Cast<Handshake>());

        public Handshake SelectedFlowControl { get => _state.SelectedFlowControl; set => _state.SelectedFlowControl = value; }

        public ICommand StartSocatCommand { get; }
        public ICommand StopSocatCommand { get; }
        public ICommand RefreshSerialPortsCommand { get; }
        public ICommand ShowSocatLogCommand { get; }
        public ICommand CheckSocatProcessesCommand { get; }
        public ICommand KillSocatProcessesCommand { get; }

        public PlcConnectionViewModel(
            IApplicationStateService applicationStateService,
            ICommunicationChannelService communicationChannelService,
            IDialogService dialogService,
            LoggingService loggingService,
            ILogger<PlcConnectionViewModel> logger)
        {
            _state = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
            _communicationChannelService = communicationChannelService ?? throw new ArgumentNullException(nameof(communicationChannelService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _loggingService = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Subscribe to service events
            _communicationChannelService.SocatStatusChanged += OnSocatStatusChanged;
            _communicationChannelService.SerialPortsChanged += OnSerialPortsChanged;
            _state.PropertyChanged += (s, e) => OnPropertyChanged(e.PropertyName);

            // Initialize commands
            StartSocatCommand = new AsyncRelayCommand(_ => StartSocatAsync(), _ => CanStartSocat());
            StopSocatCommand = new AsyncRelayCommand(_ => StopSocatAsync(), _ => CanStopSocat());
            RefreshSerialPortsCommand = new AsyncRelayCommand(_ => RefreshSerialPortsAsync());
            ShowSocatLogCommand = new RelayCommand(_ => _dialogService.ShowSocatLogWindow());
            CheckSocatProcessesCommand = new AsyncRelayCommand(_ => CheckSocatProcessesAsync());
            KillSocatProcessesCommand = new AsyncRelayCommand(_ => KillSocatProcessesAsync());

            // Initialize serial ports
            RefreshSerialPortsAsync().FireAndForget(ex => 
                _logger.LogError(ex, "Error during initial serial port refresh"));
        }

        /// <summary>
        /// Determines if socat can be started based on current state.
        /// </summary>
        private bool CanStartSocat()
        {
            return SocatStatus != "Running" && !string.IsNullOrWhiteSpace(SelectedSerialPort);
        }

        /// <summary>
        /// Determines if socat can be stopped based on current state.
        /// </summary>
        private bool CanStopSocat()
        {
            return SocatStatus == "Running";
        }

        /// <summary>
        /// Event handler for socat status changes from the service layer.
        /// </summary>
        private void OnSocatStatusChanged(object? sender, SocatStatusChangedEventArgs e)
        {
            _logger.LogInformation("Socat status changed from {PreviousStatus} to {CurrentStatus}", 
                e.PreviousStatus, e.CurrentStatus);

            // Update UI on UI thread
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                SocatStatus = e.CurrentStatus.ToString();
            });
        }

        /// <summary>
        /// Event handler for serial port changes from the service layer.
        /// </summary>
        private void OnSerialPortsChanged(object? sender, SerialPortsChangedEventArgs e)
        {
            _logger.LogInformation("Serial ports changed. Available ports: {PortCount}", e.AvailablePorts.Count);

            // Update UI on UI thread with thread-safe collection updates
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                AvailableSerialPorts.Clear();
                foreach (var portInfo in e.AvailablePorts)
                {
                    AvailableSerialPorts.Add(portInfo.PortName);
                }

                // Select first available port if none selected
                if (string.IsNullOrWhiteSpace(SelectedSerialPort) && AvailableSerialPorts.Any())
                {
                    SelectedSerialPort = AvailableSerialPorts[0];
                }
            });
        }

        /// <summary>
        /// Checks socat processes using the service layer.
        /// </summary>
        private Task CheckSocatProcessesAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    _logger.LogDebug("Checking socat processes");

                    var processInfo = _communicationChannelService.GetSocatProcessInfo();
                
                if (processInfo.TotalProcesses == 0)
                {
                    _loggingService.Log("No running socat instances detected.", LogCategory.Info);
                }
                else
                {
                    _loggingService.Log($"Socat running instances: {string.Join(", ", processInfo.ProcessIds)}", LogCategory.Info);
                }

                _logger.LogInformation("Found {ProcessCount} socat processes", processInfo.TotalProcesses);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking socat processes");
                    _loggingService.Log($"Error checking socat processes: {ex.Message}", LogCategory.Error);
                }
            });
        }

        /// <summary>
        /// Kills all socat processes using the service layer.
        /// </summary>
        private async Task KillSocatProcessesAsync()
        {
            try
            {
                _logger.LogInformation("Killing all socat processes");

                var result = await _communicationChannelService.KillAllSocatProcessesAsync().ConfigureAwait(false);
                
                if (result.IsSuccess)
                {
                    _loggingService.Log($"Successfully killed {result.Value} socat processes.", LogCategory.Info);
                    _logger.LogInformation("Killed {ProcessCount} socat processes", result.Value);
                }
                else
                {
                    _loggingService.Log($"Failed to kill socat processes: {result.Error.Message}", LogCategory.Error);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error killing socat processes");
                _loggingService.Log($"Error killing socat processes: {ex.Message}", LogCategory.Error);
            }
        }

        /// <summary>
        /// Refreshes serial ports using the service layer with thread-safe UI updates.
        /// </summary>
        private async Task RefreshSerialPortsAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing serial ports");

                var result = await _communicationChannelService.DiscoverSerialPortsAsync().ConfigureAwait(false);
                
                if (result.IsSuccess && result.Value != null)
                {
                    var discoveryResult = result.Value;
                    
                    // Update UI on UI thread with thread-safe collection updates
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        AvailableSerialPorts.Clear();
                        foreach (var portInfo in discoveryResult.AvailablePorts)
                        {
                            AvailableSerialPorts.Add(portInfo.PortName);
                        }

                        // Select first available port if none selected
                        if (string.IsNullOrWhiteSpace(SelectedSerialPort) && AvailableSerialPorts.Any())
                        {
                            SelectedSerialPort = AvailableSerialPorts[0];
                        }
                    });

                    _loggingService.Log($"Discovered {discoveryResult.AvailablePorts.Count} serial ports.", LogCategory.Info);
                    _logger.LogInformation("Discovered {PortCount} serial ports in {Duration}ms", 
                        discoveryResult.AvailablePorts.Count, discoveryResult.DiscoveryDuration.TotalMilliseconds);
                }
                else
                {
                    _loggingService.Log($"Failed to discover serial ports: {result.Error.Message}", LogCategory.Error);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing serial ports");
                _loggingService.Log($"Error refreshing serial ports: {ex.Message}", LogCategory.Error);
            }
        }

        /// <summary>
        /// Starts socat using the service layer.
        /// </summary>
        private async Task StartSocatAsync()
        {
            if (string.IsNullOrWhiteSpace(SelectedSerialPort))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a serial port.");
                return;
            }

            try
            {
                _logger.LogInformation("Starting socat bridge. Port: {SerialPort}, TCP: {TcpPort}", 
                    SelectedSerialPort, SocatTcpPort);

                var socatOptions = new SocatOptions(
                    SerialPort: SelectedSerialPort,
                    TcpPort: SocatTcpPort,
                    BaudRate: SelectedBaudRate,
                    Parity: SelectedParity.ToString(),
                    StopBits: SelectedStopBits.ToString(),
                    FlowControl: SelectedFlowControl.ToString(),
                    Verbose: SocatVerbose,
                    HexDump: SocatHexDump,
                    BlockSize: SocatBlockSize);

                var result = await _communicationChannelService.StartSocatAsync(socatOptions).ConfigureAwait(false);
                
                if (result.IsSuccess && result.Value != null)
                {
                    _loggingService.Log($"✅ Socat bridge started successfully. {SelectedSerialPort} -> TCP:{SocatTcpPort}", LogCategory.Info);
                    _logger.LogInformation("Socat started successfully. PID: {ProcessId}, Port: {SerialPort} -> TCP:{TcpPort}", 
                        result.Value.ProcessId, result.Value.SerialPort, result.Value.TcpPort);
                }
                else
                {
                    _loggingService.Log($"❌ Failed to start socat: {result.Error.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Failed to start socat: {result.Error.Message}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error starting socat");
                _loggingService.Log($"Error starting socat: {ex.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error starting socat: {ex.Message}");
            }
        }

        /// <summary>
        /// Stops socat using the service layer.
        /// </summary>
        private async Task StopSocatAsync()
        {
            try
            {
                _logger.LogInformation("Stopping socat bridge");

                var result = await _communicationChannelService.StopSocatAsync().ConfigureAwait(false);
                
                if (result.IsSuccess)
                {
                    _loggingService.Log("✅ Socat bridge stopped successfully.", LogCategory.Info);
                    _logger.LogInformation("Socat stopped successfully");
                }
                else
                {
                    _loggingService.Log($"❌ Failed to stop socat: {result.Error.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Failed to stop socat: {result.Error.Message}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error stopping socat");
                _loggingService.Log($"Error stopping socat: {ex.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error stopping socat: {ex.Message}");
            }
        }
    }
}
