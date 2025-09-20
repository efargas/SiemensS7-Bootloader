using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
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
    public class PlcConnectionViewModel : ViewModelBase
    {
        private readonly SocatService _socatService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;

        public event Action<string> SocatStatusChanged;

        private string _plcHost = "localhost";
        [Required]
        public string PlcHost
        {
            get => _plcHost;
            set
            {
                _plcHost = value;
                OnPropertyChanged();
            }
        }

        private int _plcPort = 102;
        [Range(1, 65535)]
        public int PlcPort
        {
            get => _plcPort;
            set
            {
                _plcPort = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<string> CommunicationModes { get; } = new ObservableCollection<string> { "TCP (socat)", "Serial" };
        private string _selectedCommunicationMode = "TCP (socat)";
        public string SelectedCommunicationMode
        {
            get => _selectedCommunicationMode;
            set
            {
                if (_selectedCommunicationMode != value)
                {
                    _selectedCommunicationMode = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsSocatModeSelected));
                    OnPropertyChanged(nameof(IsSerialModeSelected));
                }
            }
        }

        public bool IsSocatModeSelected => _selectedCommunicationMode == "TCP (socat)";
        public bool IsSerialModeSelected => _selectedCommunicationMode == "Serial";

        public ObservableCollection<string> AvailableSerialPorts { get; } = new ObservableCollection<string>();
        private string _selectedSerialPort = string.Empty;
        public string SelectedSerialPort
        {
            get => _selectedSerialPort;
            set
            {
                _selectedSerialPort = value;
                OnPropertyChanged();
            }
        }

        private int _socatTcpPort = 1238;
        public int SocatTcpPort
        {
            get => _socatTcpPort;
            set
            {
                _socatTcpPort = value;
                OnPropertyChanged();
            }
        }

        private bool _socatVerbose = true;
        public bool SocatVerbose
        {
            get => _socatVerbose;
            set { _socatVerbose = value; OnPropertyChanged(); }
        }

        private bool _socatHexDump = true;
        public bool SocatHexDump
        {
            get => _socatHexDump;
            set { _socatHexDump = value; OnPropertyChanged(); }
        }

        private int _socatBlockSize = 4;
        public int SocatBlockSize
        {
            get => _socatBlockSize;
            set
            {
                _socatBlockSize = value;
                OnPropertyChanged();
            }
        }

        private string _socatStatus = "Stopped";
        public string SocatStatus
        {
            get => _socatStatus;
            set
            {
                _socatStatus = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)StartSocatCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)StopSocatCommand).RaiseCanExecuteChanged();
                SocatStatusChanged?.Invoke(value);
            }
        }

        public ObservableCollection<int> AvailableBaudRates { get; } = new ObservableCollection<int> { 9600, 19200, 38400, 57600, 115200 };
        private int _selectedBaudRate = 38400;
        public int SelectedBaudRate
        {
            get => _selectedBaudRate;
            set
            {
                _selectedBaudRate = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<Parity> AvailableParities { get; } = new ObservableCollection<Parity>(Enum.GetValues(typeof(Parity)).Cast<Parity>());
        private Parity _selectedParity = Parity.Even;
        public Parity SelectedParity
        {
            get => _selectedParity;
            set
            {
                _selectedParity = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<StopBits> AvailableStopBits { get; } = new ObservableCollection<StopBits>(Enum.GetValues(typeof(StopBits)).Cast<StopBits>());
        private StopBits _selectedStopBits = StopBits.One;
        public StopBits SelectedStopBits
        {
            get => _selectedStopBits;
            set
            {
                _selectedStopBits = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<Handshake> AvailableFlowControls { get; } = new ObservableCollection<Handshake>(Enum.GetValues(typeof(Handshake)).Cast<Handshake>());
        private Handshake _selectedFlowControl = Handshake.None;
        public Handshake SelectedFlowControl
        {
            get => _selectedFlowControl;
            set
            {
                _selectedFlowControl = value;
                OnPropertyChanged();
            }
        }

        public ICommand StartSocatCommand { get; }
        public ICommand StopSocatCommand { get; }
        public ICommand RefreshSerialPortsCommand { get; }
        public ICommand ShowSocatLogCommand { get; }
        public ICommand CheckSocatProcessesCommand { get; }
        public ICommand KillSocatProcessesCommand { get; }

        public PlcConnectionViewModel(SocatService socatService, IDialogService dialogService, LoggingService loggingService)
        {
            _socatService = socatService;
            _dialogService = dialogService;
            _loggingService = loggingService;

            StartSocatCommand = new AsyncRelayCommand(_ => StartSocatAsync(), _ => IsSocatModeSelected && SocatStatus != "Running");
            StopSocatCommand = new AsyncRelayCommand(_ => StopSocatAsync(), _ => IsSocatModeSelected && SocatStatus == "Running");
            RefreshSerialPortsCommand = new RelayCommand(_ => RefreshSerialPorts());
            ShowSocatLogCommand = new RelayCommand(_ => _dialogService.ShowSocatLogWindow());
            CheckSocatProcessesCommand = new RelayCommand(_ => CheckSocatProcesses(), _ => true);
            KillSocatProcessesCommand = new RelayCommand(_ => KillSocatProcesses(), _ => true);

            RefreshSerialPorts();
        }

        private void CheckSocatProcesses()
        {
            Task.Run(() =>
            {
                var pids = SocatService.GetSocatProcessIds();
                if (pids.Length == 0)
                    _loggingService.Log("No running socat instances detected.", LogCategory.Info);
                else
                    _loggingService.Log($"Socat running instances: {string.Join(", ", pids)}", LogCategory.Info);
            });
        }

        private void KillSocatProcesses()
        {
            Task.Run(() =>
            {
                SocatService.KillAllSocatProcesses(s => _loggingService.Log(s, LogCategory.Info));
            });
        }

        private void RefreshSerialPorts()
        {
            Task.Run(() =>
            {
                var ports = System.IO.Ports.SerialPort.GetPortNames();
                Dispatcher.UIThread.Post(() =>
                {
                    AvailableSerialPorts.Clear();
                    foreach (var port in ports)
                    {
                        AvailableSerialPorts.Add(port);
                    }
                    if (AvailableSerialPorts.Any())
                    {
                        SelectedSerialPort = AvailableSerialPorts[0];
                    }
                });
            });
        }

        private Task StartSocatAsync()
        {
            return Task.Run(async () =>
            {
                try
                {
                    _socatService.Start(SelectedSerialPort, SocatTcpPort, SocatVerbose, SocatHexDump, SocatBlockSize);
                    Dispatcher.UIThread.Post(() => SocatStatus = "Running");
                }
                catch (Exception ex)
                {
                    _loggingService.Log($"Error starting socat: {ex.ToString()}", LogCategory.Error);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error starting socat: {ex.Message}");
                        SocatStatus = "Error";
                    });
                }
            });
        }

        private Task StopSocatAsync()
        {
            return Task.Run(async () =>
            {
                try
                {
                    _socatService.Stop();
                    Dispatcher.UIThread.Post(() => SocatStatus = "Stopped");
                }
                catch (Exception ex)
                {
                    _loggingService.Log($"Error stopping socat: {ex.ToString()}", LogCategory.Error);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error stopping socat: {ex.Message}");
                    });
                }
            });
        }
    }
}
