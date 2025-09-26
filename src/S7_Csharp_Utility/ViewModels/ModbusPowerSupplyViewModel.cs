#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7.Core.Abstractions.Services;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using Microsoft.Extensions.Logging;
using System.Threading;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the Modbus power supply with service layer integration.
    /// </summary>
    public class ModbusPowerSupplyViewModel : ViewModelBase
    {
        private readonly IPowerSupplyService _powerSupplyService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly ILogger<ModbusPowerSupplyViewModel> _logger;

        /// <summary>
        /// Occurs when the Modbus status changes.
        /// </summary>
        public event Action<string>? ModbusStatusChanged;

        private string _modbusHost = "localhost";
        /// <summary>
        /// Gets or sets the Modbus host.
        /// </summary>
        [Required]
        public string ModbusHost
        {
            get => _modbusHost;
            set
            {
                _modbusHost = value;
                OnPropertyChanged();
            }
        }

        private int _modbusPort = 502;
        /// <summary>
        /// Gets or sets the Modbus port.
        /// </summary>
        [Range(1, 65535)]
        public int ModbusPort
        {
            get => _modbusPort;
            set
            {
                _modbusPort = value;
                OnPropertyChanged();
            }
        }

        private ushort _modbusCoil = 1;
        /// <summary>
        /// Gets or sets the Modbus coil.
        /// </summary>
        [Range(1, 65535)]
        public ushort ModbusCoil
        {
            get => _modbusCoil;
            set
            {
                _modbusCoil = value;
                OnPropertyChanged();
            }
        }

        private byte _modbusSlaveId = 1;
        /// <summary>
        /// Gets or sets the Modbus slave ID.
        /// </summary>
        [Range(0, 255)]
        public byte ModbusSlaveId
        {
            get => _modbusSlaveId;
            set
            {
                _modbusSlaveId = value;
                OnPropertyChanged();
            }
        }

        private int _delaySeconds = 1;
        /// <summary>
        /// Gets or sets the delay in seconds.
        /// </summary>
        public int DelaySeconds
        {
            get => _delaySeconds;
            set
            {
                _delaySeconds = value;
                OnPropertyChanged();
            }
        }

        private string _modbusStatus = "Disconnected";
        /// <summary>
        /// Gets or sets the Modbus status.
        /// </summary>
        public string ModbusStatus
        {
            get => _modbusStatus;
            set
            {
                _modbusStatus = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsConnected));
                ((RelayCommand)ConnectModbusCommand).RaiseCanExecuteChanged();
                ((RelayCommand)DisconnectModbusCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)PowerOnCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)PowerOffCommand).RaiseCanExecuteChanged();
                ModbusStatusChanged?.Invoke(value);
            }
        }

        /// <summary>
        /// Gets a value indicating whether the Modbus is connected.
        /// </summary>
        public bool IsConnected => ModbusStatus == "Connected";

        /// <summary>
        /// Gets the command to connect to Modbus.
        /// </summary>
        public ICommand ConnectModbusCommand { get; }

        /// <summary>
        /// Gets the command to disconnect from Modbus.
        /// </summary>
        public ICommand DisconnectModbusCommand { get; }

        /// <summary>
        /// Gets the command to power on.
        /// </summary>
        public ICommand PowerOnCommand { get; }

        /// <summary>
        /// Gets the command to power off.
        /// </summary>
        public ICommand PowerOffCommand { get; }

        // Initialize commands in constructor
        public ModbusPowerSupplyViewModel(
            IPowerSupplyService powerSupplyService,
            IDialogService dialogService,
            LoggingService loggingService,
            ILogger<ModbusPowerSupplyViewModel> logger) : base()
        {
            _powerSupplyService = powerSupplyService ?? throw new ArgumentNullException(nameof(powerSupplyService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _loggingService = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Initialize commands
            ConnectModbusCommand = new AsyncRelayCommand(
                async _ => await ConnectModbusAsync(),
                _ => !IsConnected,
                HandleException);

            DisconnectModbusCommand = new AsyncRelayCommand(
                async _ => await DisconnectModbusAsync(),
                _ => IsConnected,
                HandleException);

            PowerOnCommand = new AsyncRelayCommand(
                async _ => await SetPowerAsync(true),
                _ => IsConnected,
                HandleException);

            PowerOffCommand = new AsyncRelayCommand(
                async _ => await SetPowerAsync(false),
                _ => IsConnected,
                HandleException);

            InitializeViewModel();
        }

        // Primary constructor initialization
        private void InitializeViewModel()
        {
            // Subscribe to power supply service events
            _powerSupplyService.ConnectionStatusChanged += OnConnectionStatusChanged;
            _powerSupplyService.PowerStateChanged += OnPowerStateChanged;
        }

        /// <summary>
        /// Handles exceptions from async commands.
        /// </summary>
        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in ModbusPowerSupplyViewModel");
            _loggingService.Log($"An unexpected error occurred: {ex}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        /// <summary>
        /// Event handler for power supply connection status changes.
        /// </summary>
        private void OnConnectionStatusChanged(object? sender, PowerSupplyConnectionStatusChangedEventArgs e)
        {
            _logger.LogInformation("Power supply connection status changed from {PreviousStatus} to {CurrentStatus}", 
                e.PreviousStatus, e.CurrentStatus);

            // Update UI status on UI thread
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                ModbusStatus = e.CurrentStatus switch
                {
                    PowerSupplyConnectionStatus.Disconnected => "Disconnected",
                    PowerSupplyConnectionStatus.Connecting => "Connecting",
                    PowerSupplyConnectionStatus.Connected => "Connected",
                    PowerSupplyConnectionStatus.Error => "Error",
                    _ => "Unknown"
                };

                if (e.CurrentStatus == PowerSupplyConnectionStatus.Error && !string.IsNullOrEmpty(e.ErrorMessage))
                {
                    _loggingService.Log($"Power supply connection error: {e.ErrorMessage}", LogCategory.Error);
                }
            });
        }

        /// <summary>
        /// Event handler for power state changes.
        /// </summary>
        private void OnPowerStateChanged(object? sender, PowerStateChangedEventArgs e)
        {
            _logger.LogInformation("Power state changed from {PreviousState} to {CurrentState} for coil {CoilAddress}", 
                e.PreviousState, e.CurrentState, e.CoilAddress);

            var stateText = e.CurrentState switch
            {
                PowerState.On => "ON",
                PowerState.Off => "OFF",
                _ => "UNKNOWN"
            };

            _loggingService.Log($"Power state changed to {stateText} for coil {e.CoilAddress}", LogCategory.Info);
        }

        /// <summary>
        /// Connects to the Modbus power supply using the service layer.
        /// </summary>
        private async Task ConnectModbusAsync()
        {
            _logger.LogInformation("Attempting to connect to Modbus power supply at {Host}:{Port}", ModbusHost, ModbusPort);
            
            try
            {
                var config = new PowerSupplyConfig
                {
                    Host = ModbusHost,
                    Port = ModbusPort,
                    SlaveId = ModbusSlaveId,
                    CoilAddress = ModbusCoil,
                    ConnectionTimeout = TimeSpan.FromSeconds(10),
                    OperationTimeout = TimeSpan.FromSeconds(5)
                };

                var connected = await _powerSupplyService.ConnectAsync(config, CancellationToken.None);
                
                if (connected)
                {
                    _loggingService.Log($"Successfully connected to Modbus power supply at {ModbusHost}:{ModbusPort}", LogCategory.Info);
                }
                else
                {
                    _loggingService.Log($"Failed to connect to Modbus power supply at {ModbusHost}:{ModbusPort}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Connection Failed", "Failed to connect to the Modbus power supply. Please check your settings and try again.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error connecting to Modbus power supply");
                _loggingService.Log($"Error connecting to Modbus: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Connection Error", $"Error connecting to Modbus: {ex.Message}");
            }
        }

        /// <summary>
        /// Disconnects from the Modbus power supply using the service layer.
        /// </summary>
        private async Task DisconnectModbusAsync()
        {
            _logger.LogInformation("Disconnecting from Modbus power supply");
            
            try
            {
                await _powerSupplyService.DisconnectAsync();
                _loggingService.Log("Disconnected from Modbus power supply", LogCategory.Info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disconnecting from Modbus power supply");
                _loggingService.Log($"Error disconnecting from Modbus: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Disconnection Error", $"Error disconnecting from Modbus: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets the power state using the service layer.
        /// </summary>
        /// <param name="on">True to turn on, false to turn off.</param>
        public async Task SetPowerAsync(bool on)
        {
            if (!IsConnected)
            {
                _loggingService.Log("Cannot set power: Modbus not connected.", LogCategory.Warning);
                return;
            }

            _logger.LogInformation("Setting power {PowerState} for coil {CoilAddress}", on ? "ON" : "OFF", ModbusCoil);

            try
            {
                var result = await _powerSupplyService.SetPowerAsync(ModbusCoil, on, CancellationToken.None);
                
                if (result.IsSuccess)
                {
                    _loggingService.Log($"Power set to {(on ? "ON" : "OFF")} successfully in {result.Duration.TotalMilliseconds:F0}ms", LogCategory.Info);
                }
                else
                {
                    _loggingService.Log($"Failed to set power: {result.ErrorMessage}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Power Control Error", $"Failed to set power: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting power state");
                _loggingService.Log($"Failed to set power: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Power Control Error", $"Failed to set power: {ex.Message}");
            }
        }

        /// <summary>
        /// Power cycles the PLC using the service layer.
        /// </summary>
        /// <param name="delaySeconds">The delay in seconds between turning off and on.</param>
        public async Task PowerCycleAsync(int delaySeconds)
        {
            if (!IsConnected)
            {
                _loggingService.Log("Cannot power cycle: Modbus not connected.", LogCategory.Warning);
                return;
            }

            _logger.LogInformation("Starting power cycle for coil {CoilAddress} with {DelaySeconds}s delay", ModbusCoil, delaySeconds);
            _loggingService.Log($"[POWER] Starting power cycle with {delaySeconds}s delay...", LogCategory.Info);

            try
            {
                var result = await _powerSupplyService.PowerCycleAsync(ModbusCoil, TimeSpan.FromSeconds(delaySeconds), CancellationToken.None);
                
                if (result.IsSuccess)
                {
                    _loggingService.Log($"✅ Power cycle completed successfully in {result.Duration.TotalSeconds:F1}s", LogCategory.Info);
                    _logger.LogInformation("Power cycle completed successfully in {Duration}ms", result.Duration.TotalMilliseconds);
                }
                else
                {
                    _loggingService.Log($"❌ Power cycle failed: {result.ErrorMessage}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Power Cycle Error", $"Power cycle failed: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during power cycle");
                _loggingService.Log($"❌ Power cycle failed: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Power Cycle Error", $"Power cycle failed: {ex.Message}");
            }
        }
    }
}
