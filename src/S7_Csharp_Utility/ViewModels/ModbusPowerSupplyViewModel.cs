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
    public class ModbusPowerSupplyViewModel : ViewModelBase
    {
        private readonly PowerController _powerController;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;

        public event Action<string> ModbusStatusChanged;

        private string _modbusHost = "localhost";
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

        public bool IsConnected => ModbusStatus == "Connected";

        public ICommand ConnectModbusCommand { get; }
        public ICommand DisconnectModbusCommand { get; }
        public ICommand PowerOnCommand { get; }
        public ICommand PowerOffCommand { get; }

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
