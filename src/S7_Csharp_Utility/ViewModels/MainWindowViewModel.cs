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
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";
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

        public LoggingService Logging { get; }
        public SocatLoggerService SocatLogging { get; }
        private readonly PowerController _powerController;

        public ICommand PowerOnCommand { get; }
        public ICommand PowerOffCommand { get; }

        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x10000000";
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
        public bool IsUploadingStager
        {
            get => _isUploadingStager;
            set
            {
                _isUploadingStager = value;
                OnPropertyChanged();
                (UploadStagerCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private bool _isDumpingMemory;
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

        public string PayloadsPath
        {
            get => _payloadsPath;
            set { _payloadsPath = value; OnPropertyChanged(); }
        }
        private string _payloadsPath = string.Empty;
        public string DumpsPath
        {
            get => _dumpsPath;
            set { _dumpsPath = value; OnPropertyChanged(); }
        }
        private string _dumpsPath = string.Empty;
        public string LogsPath
        {
            get => _logsPath;
            set { _logsPath = value; OnPropertyChanged(); }
        }
        private string _logsPath = string.Empty;
        public string ExtractionPath
        {
            get => _extractionPath;
            set { _extractionPath = value; OnPropertyChanged(); }
        }
        private string _extractionPath = string.Empty;

        public ICommand BrowsePayloadsFolderCommand { get; }
        public ICommand BrowseDumpsFolderCommand { get; }
        public ICommand BrowseLogsFolderCommand { get; }
        public ICommand BrowseExtractionFolderCommand { get; }
        public ICommand SavePathsCommand { get; }

        public ICommand UploadStagerCommand { get; }
        public ICommand DumpMemoryCommand { get; }
        public ICommand BrowseCompareFolderCommand { get; }
        public ICommand BrowseCompareFile1Command { get; }
        public ICommand BrowseCompareFile2Command { get; }
        public ICommand CompareDumpsCommand { get; }
        public ICommand CompareTwoFilesCommand { get; }

        private readonly SocatService _socatService;
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

        private int _socatTcpPort = 8888;
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

        public ICommand StartSocatCommand { get; }
        public ICommand StopSocatCommand { get; }
        public ICommand RefreshSerialPortsCommand { get; }
        public ICommand ShowSocatLogCommand { get; }
        public ICommand SaveConfigurationCommand { get; }
        public ICommand LoadConfigurationCommand { get; }

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

        public ObservableCollection<int> AvailableBaudRates { get; } = new ObservableCollection<int> { 9600, 19200, 38400, 57600, 115200 };
        private int _selectedBaudRate = 115200;
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
        private Parity _selectedParity = Parity.None;
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


        private string _compareFolder = string.Empty;
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

        private readonly Interfaces.IDialogService _dialogService;
        private readonly ConfigurationService _configService;

        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PayloadManager payloadManager, Interfaces.IDialogService dialogService, SocatService socatService, ConfigurationService configService, SocatLoggerService socatLoggerService)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _powerController = powerController;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            _socatService = socatService;
            _configService = configService;

            PowerOnCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true, ModbusSlaveId));
            PowerOffCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false, ModbusSlaveId));
            UploadStagerCommand = new Commands.RelayCommand(async _ => await UploadStager(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
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

        private async Task UploadStager()
        {
            IsUploadingStager = true;
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            try
            {
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false);
                Logging.Log($"Waiting for {DelaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(DelaySeconds * 1000);
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true);

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
