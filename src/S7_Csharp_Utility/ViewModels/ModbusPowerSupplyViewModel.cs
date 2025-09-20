#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the Modbus power supply.
    /// </summary>
    public class ModbusPowerSupplyViewModel : ViewModelBase
    {
        private readonly PowerController _powerController;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;

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

        /// <summary>
        /// Initializes a new instance of the <see cref="ModbusPowerSupplyViewModel"/> class.
        /// </summary>
        public ModbusPowerSupplyViewModel(PowerController powerController, IDialogService dialogService, LoggingService loggingService)
        {
            _powerController = powerController;
            _dialogService = dialogService;
            _loggingService = loggingService;

            ConnectModbusCommand = new RelayCommand(_ => ConnectModbusAsync(), _ => ModbusStatus != "Connected");
            DisconnectModbusCommand = new RelayCommand(_ => DisconnectModbus(), _ => ModbusStatus == "Connected");
            PowerOnCommand = new AsyncRelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, true, ModbusSlaveId), _ => ModbusStatus == "Connected");
            PowerOffCommand = new AsyncRelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, false, ModbusSlaveId), _ => ModbusStatus == "Connected");
        }

        private Task ConnectModbusAsync()
        {
            return Task.Run(async () =>
            {
                try
                {
                    await _powerController.ConnectAsync(ModbusHost, ModbusPort);
                    Dispatcher.UIThread.Post(() => ModbusStatus = _powerController.IsConnected ? "Connected" : "Error");
                }
                catch (Exception ex)
                {
                    _loggingService.Log($"Error connecting to Modbus: {ex.ToString()}", LogCategory.Error);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error connecting to Modbus: {ex.Message}");
                        ModbusStatus = "Error";
                    });
                }
            });
        }

        private void DisconnectModbus()
        {
            _powerController.Disconnect();
            ModbusStatus = "Disconnected";
        }

        /// <summary>
        /// Sets the power of the PLC.
        /// </summary>
        /// <param name="on">True to turn on, false to turn off.</param>
        public async Task SetPowerAsync(bool on)
        {
            if (ModbusStatus != "Connected")
            {
                _loggingService.Log("Cannot set power: Modbus not connected.", LogCategory.Warning);
                return;
            }
            try
            {
                await _powerController.SetPowerAsync(ModbusCoil, on, ModbusSlaveId);
                _loggingService.Log($"Power set to {(on ? "ON" : "OFF")}", LogCategory.Info);
            }
            catch (Exception ex)
            {
                _loggingService.Log($"Failed to set power: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Failed to set power: {ex.Message}");
            }
        }

        /// <summary>
        /// Power cycles the PLC.
        /// </summary>
        /// <param name="delaySeconds">The delay in seconds between turning off and on.</param>
        public async Task PowerCycleAsync(int delaySeconds)
        {
            _loggingService.Log("[POWER] Turning PLC power OFF...", LogCategory.Info);
            await SetPowerAsync(false);
            _loggingService.Log($"[POWER] Waiting {delaySeconds} seconds before powering on...", LogCategory.Info);
            await Task.Delay(delaySeconds * 1000);
            _loggingService.Log("[POWER] Turning PLC power ON...", LogCategory.Info);
            await SetPowerAsync(true);
        }
    }
}
