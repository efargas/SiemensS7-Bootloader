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
        private readonly IApplicationStateService _state;
        private readonly IPowerSupplyService _powerSupplyService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly ILogger<ModbusPowerSupplyViewModel> _logger;

        public event Action<string>? ModbusStatusChanged;

        [Required(ErrorMessage = "Modbus host is required")]
        [RegularExpression(@"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
            ErrorMessage = "Must be a valid IP address (e.g., 192.168.1.100) or hostname (e.g., localhost)")]
        public string ModbusHost { get => _state.ModbusHost; set => _state.ModbusHost = value; }

        [Range(1, 65535, ErrorMessage = "Modbus port must be between 1 and 65535")]
        [Display(Name = "Modbus Port", Description = "TCP port for Modbus communication (default: 502)")]
        public int ModbusPort { get => _state.ModbusPort; set => _state.ModbusPort = value; }

        [Range(1, 65535, ErrorMessage = "Modbus coil address must be between 1 and 65535")]
        [Display(Name = "Coil Address", Description = "Modbus coil address for power control")]
        public ushort ModbusCoil { get => _state.ModbusCoil; set => _state.ModbusCoil = value; }

        [Range(0, 255, ErrorMessage = "Modbus slave ID must be between 0 and 255")]
        [Display(Name = "Slave ID", Description = "Modbus slave device ID")]
        public byte ModbusSlaveId { get => _state.ModbusSlaveId; set => _state.ModbusSlaveId = value; }

        [Range(0, 300, ErrorMessage = "Delay must be between 0 and 300 seconds (5 minutes)")]
        [Display(Name = "Power Cycle Delay", Description = "Delay in seconds between power off and power on")]
        public int DelaySeconds { get => _state.DelaySeconds; set => _state.DelaySeconds = value; }

        private string _modbusStatus = "Disconnected";
        public string ModbusStatus
        {
            get => _state.ModbusStatus;
            set
            {
                if (_state.ModbusStatus != value)
                {
                    _state.ModbusStatus = value;
                    OnPropertyChanged(); // Notify local listeners
                    OnPropertyChanged(nameof(IsConnected));
                    RaiseCanExecuteChangedSafely(ConnectModbusCommand);
                    RaiseCanExecuteChangedSafely(DisconnectModbusCommand);
                    RaiseCanExecuteChangedSafely(PowerOnCommand);
                    RaiseCanExecuteChangedSafely(PowerOffCommand);
                    ModbusStatusChanged?.Invoke(value);
                }
            }
        }

        public bool IsConnected => ModbusStatus == "Connected";

        public ICommand ConnectModbusCommand { get; }
        public ICommand DisconnectModbusCommand { get; }
        public ICommand PowerOnCommand { get; }
        public ICommand PowerOffCommand { get; }

        public ModbusPowerSupplyViewModel(
            IApplicationStateService applicationStateService,
            IPowerSupplyService powerSupplyService,
            IDialogService dialogService,
            LoggingService loggingService,
            ILogger<ModbusPowerSupplyViewModel> logger) : base()
        {
            _state = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
            _powerSupplyService = powerSupplyService ?? throw new ArgumentNullException(nameof(powerSupplyService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _loggingService = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _state.PropertyChanged += (s, e) => OnPropertyChanged(e.PropertyName);

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
        /// Safely raises CanExecuteChanged for both RelayCommand and AsyncRelayCommand types.
        /// </summary>
        /// <param name="command">The command to raise CanExecuteChanged for.</param>
        private void RaiseCanExecuteChangedSafely(ICommand command)
        {
            try
            {
                switch (command)
                {
                    case RelayCommand relayCommand:
                        relayCommand.RaiseCanExecuteChanged();
                        break;
                    case AsyncRelayCommand asyncRelayCommand:
                        asyncRelayCommand.RaiseCanExecuteChanged();
                        break;
                    default:
                        // For other ICommand implementations, we can't raise CanExecuteChanged
                        // but this prevents the InvalidCastException
                        _logger.LogDebug("Command type {CommandType} does not support RaiseCanExecuteChanged", command.GetType().Name);
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to raise CanExecuteChanged for command {CommandType}", command.GetType().Name);
            }
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
