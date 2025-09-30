#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the Modbus power supply.
    /// </summary>
    public class ModbusPowerSupplyViewModel : ViewModelBase
    {
        private readonly IPowerController _powerController;
        private readonly IDialogService _dialogService;
        private readonly ILogger<ModbusPowerSupplyViewModel> _logger;

        /// <summary>
        /// Occurs when the Modbus status changes.
        /// </summary>
        public event Action<string>? ModbusStatusChanged;

        private string _modbusHost = "localhost";
        [Required]
        public string ModbusHost
        {
            get => _modbusHost;
            set => SetProperty(ref _modbusHost, value);
        }

        private int _modbusPort = 502;
        [Range(1, 65535)]
        public int ModbusPort
        {
            get => _modbusPort;
            set => SetProperty(ref _modbusPort, value);
        }

        private int _modbusCoil = 1;
        [Range(1, 65535)]
        public int ModbusCoil
        {
            get => _modbusCoil;
            set => SetProperty(ref _modbusCoil, value);
        }

        private int _delaySeconds = 1;
        public int DelaySeconds
        {
            get => _delaySeconds;
            set => SetProperty(ref _delaySeconds, value);
        }

        private string _modbusStatus = "Ready";
        public string ModbusStatus
        {
            get => _modbusStatus;
            set
            {
                if (SetProperty(ref _modbusStatus, value))
                {
                    ((AsyncRelayCommand)PowerCycleCommand).RaiseCanExecuteChanged();
                    ModbusStatusChanged?.Invoke(value);
                }
            }
        }

        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                if(SetProperty(ref _isBusy, value))
                {
                    ((AsyncRelayCommand)PowerCycleCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public ICommand PowerCycleCommand { get; }

        public ModbusPowerSupplyViewModel(
            IPowerController powerController,
            IDialogService dialogService,
            ILogger<ModbusPowerSupplyViewModel> logger)
        {
            _powerController = powerController ?? throw new ArgumentNullException(nameof(powerController));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            PowerCycleCommand = new AsyncRelayCommand(PowerCycleAsync, _ => !IsBusy, HandleException);
        }

        private async Task PowerCycleAsync()
        {
            IsBusy = true;
            ModbusStatus = "Power Cycling...";
            try
            {
                await _powerController.PowerCycleAsync(ModbusHost, ModbusPort, ModbusCoil, DelaySeconds);
                ModbusStatus = "Ready";
                _logger.LogInformation("Power cycle completed successfully for host {Host} on coil {Coil}", ModbusHost, ModbusCoil);
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void HandleException(Exception ex)
        {
            ModbusStatus = "Error";
            _logger.LogError(ex, "An error occurred during power cycle operation.");
            _dialogService.ShowMessageAsync("Error", $"An error occurred during power cycle: {ex.Message}");
        }

        public void LoadFromAppConfig(ApplicationConfiguration config)
        {
            ModbusHost = config.ModbusHost ?? "localhost";
            ModbusPort = config.ModbusPort;
            ModbusCoil = config.ModbusCoil;
            DelaySeconds = config.DelaySeconds;
        }

        public void SaveToAppConfig(ApplicationConfiguration config)
        {
            config.ModbusHost = ModbusHost;
            config.ModbusPort = ModbusPort;
            config.ModbusCoil = ModbusCoil;
            config.DelaySeconds = DelaySeconds;
        }
    }
}