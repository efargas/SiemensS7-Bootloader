#nullable enable
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using S7.Net;
using S7.Net.Interfaces;
using S7.Net.Channels;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO.Ports;
using System.Threading;
using Avalonia.Threading;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        public PlcConnectionViewModel? PlcConnectionViewModel { get; }
        public ModbusPowerSupplyViewModel? ModbusPowerSupplyViewModel { get; }
        public ConfigurationViewModel ConfigurationViewModel { get; }
        public FileCompareViewModel FileCompareViewModel { get; }
        public LoggingService Logging { get; }
        public SocatLoggerService SocatLogging { get; }
        private readonly PayloadManager _payloadManager;

        private string _dumpAddress = "0x691E28";
        [Required]
        [RegularExpression(@"^0x[0-9a-fA-F]+$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000)")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set => SetProperty(ref _dumpAddress, value);
        }

        private uint _dumpLength = 16;
        [Range(1, uint.MaxValue)]
        public uint DumpLength
        {
            get => _dumpLength;
            set => SetProperty(ref _dumpLength, value);
        }

        private bool _isUploadingStager;
        public bool IsUploadingStager
        {
            get => _isUploadingStager;
            set
            {
                _isUploadingStager = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
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
                ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CancelDumpCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
            }
        }

        private CancellationTokenSource? _dumpCancellationTokenSource;

        private bool _isComparing;
        public bool IsComparing
        {
            get => _isComparing;
            set
            {
                _isComparing = value;
                OnPropertyChanged();
                                ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
            }
        }

        private double _dumpProgressPercentage;
        public double DumpProgressPercentage
        {
            get => _dumpProgressPercentage;
            set => SetProperty(ref _dumpProgressPercentage, value);
        }

        private string _dumpProgressBytes = "Read: 0 / 0 bytes";
        public string DumpProgressBytes
        {
            get => _dumpProgressBytes;
            set => SetProperty(ref _dumpProgressBytes, value);
        }

        private string _dumpProgressTime = "Elapsed: 0s | Remaining: calculating...";
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set => SetProperty(ref _dumpProgressTime, value);
        }

        private bool _stagerInstalled;
        public bool StagerInstalled
        {
            get => _stagerInstalled;
            set
            {
                _stagerInstalled = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
            }
        }

        public ObservableCollection<PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<PayloadInfo>();

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        public ICommand LoadProfileCommand { get; }
        public ICommand StartExploitSequenceCommand { get; }
        public ICommand DumpMemoryCommand { get; }
        public ICommand CancelDumpCommand { get; }
        public ICommand ShowProfileManagementCommand { get; }
        public ICommand ShowFirmwareUnpackerCommand { get; }
        public ICommand ShowHexViewerCommand { get; }
        public ICommand SaveConfigurationCommand { get; }
        public ICommand ExitCommand { get; }
        public ICommand CancelScanCommand { get; }

        private readonly IDialogService _dialogService;
        public ConfigurationService ConfigService { get; }

        private CancellationTokenSource? _scanCancellationTokenSource;
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

        public ObservableCollection<MemoryRegion> MemoryRegions => LoadedProfile?.Regions ?? new ObservableCollection<MemoryRegion>();

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

        public IViewService ViewService { get; }

        public MainWindowViewModel(
            LoggingService loggingService,
            SocatLoggerService socatLoggerService,
            PayloadManager payloadManager,
            IDialogService dialogService,
            ConfigurationService configService,
            IViewService viewService,
            PlcConnectionViewModel plcConnectionViewModel,
            ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
            ConfigurationViewModel configurationViewModel,
            FileCompareViewModel fileCompareViewModel)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            ConfigService = configService;
            ViewService = viewService;
            PlcConnectionViewModel = plcConnectionViewModel;
            ModbusPowerSupplyViewModel = modbusPowerSupplyViewModel;
            ConfigurationViewModel = configurationViewModel;
            FileCompareViewModel = fileCompareViewModel;

            if (PlcConnectionViewModel != null)
            {
                PlcConnectionViewModel.SocatStatusChanged += (status) => ((AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
            }
            if (ModbusPowerSupplyViewModel != null)
            {
                ModbusPowerSupplyViewModel.ModbusStatusChanged += (status) => ((AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
            }

            StartExploitSequenceCommand = new AsyncRelayCommand(_ => StartExploitSequenceAsync(), _ => PlcConnectionViewModel?.SocatStatus == "Running" && ModbusPowerSupplyViewModel?.ModbusStatus == "Connected" && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            DumpMemoryCommand = new AsyncRelayCommand(_ => DumpMemoryAsync(), _ => StagerInstalled && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            CancelDumpCommand = new RelayCommand(_ => CancelDump(), _ => IsDumpingMemory);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), _ => IsScanning);
            LoadProfileCommand = new AsyncRelayCommand(_ => LoadProfileAsync(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            SaveConfigurationCommand = new AsyncRelayCommand(_ => SaveConfigurationOnExit(), _ => true, HandleException);

            ShowProfileManagementCommand = new RelayCommand(_ => ShowProfileManagement());
            ShowFirmwareUnpackerCommand = new RelayCommand(_ => ShowFirmwareUnpacker());
            ShowHexViewerCommand = new RelayCommand(_ => ShowHexViewer());
            ExitCommand = new RelayCommand(_ => Exit());
            
            StartScanPayloads();
        }

        private void HandleException(Exception ex)
        {
            Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private void ShowProfileManagement()
        {
            ViewService.ShowProfileManagementWindow(ConfigService, profile =>
            {
                if (profile != null)
                {
                    LoadedProfile = profile;
                }
            });
        }

        private void ShowFirmwareUnpacker()
        {
            if (ConfigurationViewModel.ExtractionPath != null)
            {
                ViewService.ShowFirmwareUnpackerWindow(ConfigurationViewModel.ExtractionPath);
            }
        }
        private void ShowHexViewer() => ViewService.ShowHexViewerWindow();
        private void Exit() => ViewService.Exit();

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

        private ICommunicationChannel? CreateCommunicationChannel()
        {
            if (PlcConnectionViewModel?.SelectedCommunicationMode == "TCP (socat)")
            {
                return new TcpChannel(PlcConnectionViewModel.PlcHost ?? "localhost", PlcConnectionViewModel.PlcPort);
            }
            else if (PlcConnectionViewModel?.SelectedCommunicationMode == "Serial" && PlcConnectionViewModel.SelectedSerialPort != null)
            {
                return new SerialChannel(PlcConnectionViewModel.SelectedSerialPort, PlcConnectionViewModel.SelectedBaudRate, PlcConnectionViewModel.SelectedParity, PlcConnectionViewModel.SelectedStopBits, PlcConnectionViewModel.SelectedFlowControl);
            }
            return null;
        }
        
        private async Task StartExploitSequenceAsync()
        {
            IsUploadingStager = true;
            ICommunicationChannel? channel = null;
            try
            {
                Logging.Log("[EXPLOIT] Starting exploit sequence...", LogCategory.Info);
                await ModbusPowerSupplyViewModel.PowerCycleAsync(ModbusPowerSupplyViewModel.DelaySeconds);
                await Task.Delay(50);

                Logging.Log("[CONNECTION] Creating communication channel...", LogCategory.Info);
                channel = CreateCommunicationChannel();

                if (channel == null) throw new Exception("Could not create communication channel. PLC Connection View Model is not initialized.");

                Logging.Log($"[CONNECTION] Connecting to PLC at {PlcConnectionViewModel.PlcHost}:{PlcConnectionViewModel.PlcPort}...", LogCategory.Info);
                await channel.ConnectAsync();

                if (!channel.IsConnected) throw new Exception("Failed to establish connection to PLC");

                Logging.Log("[CONNECTION] ✅ Connected to PLC successfully", LogCategory.Info);
                var plcClient = new PlcClient(channel, message => Logging.Log(message, LogCategory.Info));
                await RunStagerSequenceAsync(plcClient);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is System.IO.IOException)
            {
                var errorType = ex is TimeoutException ? "Timeout" : "Connection";
                Logging.Log($"[ERROR] ⏱️ {errorType} during stager sequence: {ex}", LogCategory.Error);
                await _dialogService.ShowMessageAsync($"{errorType} Error", $"The operation timed out. Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Logging.Log($"[ERROR] ❌ Unexpected error during stager sequence: {ex}", LogCategory.Error);
                if (ex.InnerException != null) Logging.Log($"[ERROR] Inner exception: {ex.InnerException}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"An error occurred during the stager sequence: {ex.Message}");
            }
            finally
            {
                channel?.Disconnect();
                IsUploadingStager = false;
            }
        }

        private async Task RunStagerSequenceAsync(PlcClient plcClient)
        {
            StagerInstalled = false;
            if (!plcClient.IsConnected) return;

            if (await plcClient.PerformHandshakeAsync())
            {
                await plcClient.GetVersion();
                byte[] stagerPayload = await _payloadManager.GetStagerPayloadAsync(ConfigurationViewModel.PayloadsPath);
                Logging.Log($"Loaded stager payload ({stagerPayload.Length} bytes) from {ConfigurationViewModel.PayloadsPath}.", LogCategory.Info);
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
                ICommunicationChannel? channel = null;
                try
                {
                    if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                    {
                        await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address.");
                        return;
                    }

                    channel = CreateCommunicationChannel();
                    if (channel == null) throw new Exception("Could not create communication channel.");

                    await channel.ConnectAsync();
                    var plcClient = new PlcClient(channel, message => Logging.Log(message, LogCategory.Info));
                    await RunDumpSequenceAsync(plcClient, address, DumpLength, _dumpCancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    Logging.Log("Memory dump operation was cancelled by user.", LogCategory.Info);
                }
                catch (Exception ex)
                {
                    Logging.Log($"An error occurred during the dump sequence: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", ex.Message);
                }
                finally
                {
                    channel?.Disconnect();
                    IsDumpingMemory = false;
                }
            }
            _dumpCancellationTokenSource = null;
        }

        private void CancelDump() => _dumpCancellationTokenSource?.Cancel();

        private async Task RunDumpSequenceAsync(PlcClient plcClient, uint address, uint length, CancellationToken cancellationToken)
        {
            Logging.Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);
            byte[] dumperPayload = await _payloadManager.GetMemoryDumperPayloadAsync(ConfigurationViewModel.PayloadsPath);
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes) from {ConfigurationViewModel.PayloadsPath}.", LogCategory.Info);
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
            string resolvedDumpsPath = ApplicationConfiguration.ResolvePath(ConfigurationViewModel.DumpsPath, ApplicationConfiguration.GetDefaultDumpsPath());
            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            string fullPath = System.IO.Path.Combine(resolvedDumpsPath, outFilename);
            await System.IO.File.WriteAllBytesAsync(fullPath, dumpedData, cancellationToken);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {fullPath} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = await ConfigService.LoadConfigurationAsync(path);
                if (config != null)
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

            string resolvedLogsPath = ApplicationConfiguration.ResolvePath(ConfigurationViewModel.LogsPath, ApplicationConfiguration.GetDefaultLogsPath());
            Logging.UpdateLogsPath(resolvedLogsPath);
            SocatLogging.UpdateLogsPath(resolvedLogsPath);
        }

        public async Task SaveConfigurationOnExit()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = new ApplicationConfiguration
                {
                    PlcHost = PlcConnectionViewModel.PlcHost,
                    PlcPort = PlcConnectionViewModel.PlcPort,
                    ModbusHost = ModbusPowerSupplyViewModel.ModbusHost,
                    ModbusPort = ModbusPowerSupplyViewModel.ModbusPort,
                    ModbusCoil = ModbusPowerSupplyViewModel.ModbusCoil,
                    DelaySeconds = ModbusPowerSupplyViewModel.DelaySeconds,
                    DumpAddress = DumpAddress,
                    DumpLength = DumpLength,
                    CompareFolder = FileCompareViewModel.CompareFolder,
                    CompareFile1 = FileCompareViewModel.CompareFile1,
                    CompareFile2 = FileCompareViewModel.CompareFile2,
                    SelectedSerialPort = PlcConnectionViewModel.SelectedSerialPort,
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

        private void CancelScan() => _scanCancellationTokenSource?.Cancel();

        private void StartScanPayloads()
        {
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            ScanPayloadsAsync(_scanCancellationTokenSource.Token).FireAndForget(ex => Logging.Log($"Error during payload scan: {ex.Message}", LogCategory.Error));
        }

        private async Task ScanPayloadsAsync(CancellationToken cancellationToken)
        {
            if (IsScanning || string.IsNullOrWhiteSpace(ConfigurationViewModel.PayloadsPath))
                return;

            IsScanning = true;
            ((RelayCommand)CancelScanCommand).RaiseCanExecuteChanged();

            try
            {
                var payloads = await _payloadManager.ScanPayloadsAsync(ConfigurationViewModel.PayloadsPath, cancellationToken);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    DiscoveredPayloads.Clear();
                    foreach (var payload in payloads)
                    {
                        DiscoveredPayloads.Add(payload);
                    }
                });

                Logging.Log($"Payload scan completed. Found {payloads.Count} payload files in {ConfigurationViewModel.PayloadsPath}", LogCategory.Info);

                foreach (var payload in payloads)
                {
                    Logging.Log($"  - {payload.Type}: {payload.RelativePath} ({payload.Size} bytes)", LogCategory.Debug);
                }
            }
            catch (OperationCanceledException)
            {
                Logging.Log("Payload scan was cancelled.", LogCategory.Info);
            }
            catch (Exception ex)
            {
                Logging.Log($"Error scanning payloads: {ex.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error scanning payloads: {ex.Message}");
            }
            finally
            {
                IsScanning = false;
                ((RelayCommand)CancelScanCommand).RaiseCanExecuteChanged();
            }
        }
    }
}
