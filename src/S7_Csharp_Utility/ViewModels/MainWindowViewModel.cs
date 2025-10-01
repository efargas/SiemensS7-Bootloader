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
using S7.Core.Commands;

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
        private readonly ICommandHandler<StagerInstallOptions> _stagerInstallHandler;
        private readonly ICommandHandler<MemoryDumpOptions> _memoryDumpHandler;
        private readonly IDialogService _dialogService;
        public IConfigurationService ConfigService { get; }


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
            IDialogService dialogService,
            IConfigurationService configService,
            IViewService viewService,
            ICommandHandler<StagerInstallOptions> stagerInstallHandler,
            ICommandHandler<MemoryDumpOptions> memoryDumpHandler,
            PlcConnectionViewModel plcConnectionViewModel,
            ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
            ConfigurationViewModel configurationViewModel,
            FileCompareViewModel fileCompareViewModel)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _dialogService = dialogService;
            ConfigService = configService;
            ViewService = viewService;
            _stagerInstallHandler = stagerInstallHandler;
            _memoryDumpHandler = memoryDumpHandler;
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

        private async Task StartExploitSequenceAsync()
        {
            IsUploadingStager = true;
            StagerInstalled = false;
            try
            {
                var options = new StagerInstallOptions
                {
                    ChannelConfig = new CommunicationChannelConfig
                    {
                        Mode = PlcConnectionViewModel.SelectedCommunicationMode,
                        Host = PlcConnectionViewModel.PlcHost,
                        Port = PlcConnectionViewModel.PlcPort,
                        SerialPort = PlcConnectionViewModel.SelectedSerialPort,
                        BaudRate = PlcConnectionViewModel.SelectedBaudRate,
                        Parity = PlcConnectionViewModel.SelectedParity,
                        StopBits = PlcConnectionViewModel.SelectedStopBits,
                        FlowControl = PlcConnectionViewModel.SelectedFlowControl
                    },
                    PowerConfig = new PowerControllerConfig
                    {
                        Host = ModbusPowerSupplyViewModel.ModbusHost,
                        Port = ModbusPowerSupplyViewModel.ModbusPort,
                        Coil = ModbusPowerSupplyViewModel.ModbusCoil,
                        DelaySeconds = ModbusPowerSupplyViewModel.DelaySeconds
                    },
                    PayloadPath = ConfigurationViewModel.PayloadsPath,
                    PerformHandshake = true,
                    GetVersionInfo = true
                };

                var result = await _stagerInstallHandler.HandleAsync(options);

                if (result.IsSuccess && result.ResultObject is StagerInstallResult stagerResult)
                {
                    StagerInstalled = stagerResult.IsInstalled;
                    Logging.Log("Stager installation successful.", LogCategory.Info);
                }
                else
                {
                    await _dialogService.ShowMessageAsync("Error", result.ErrorMessage ?? "An unknown error occurred during stager installation.");
                }
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
            finally
            {
                IsUploadingStager = false;
            }
        }

        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            using (_dumpCancellationTokenSource = new CancellationTokenSource())
            {
                try
                {
                    if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                    {
                        await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address.");
                        return;
                    }

                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var progress = new Progress<(long bytesRead, long totalBytes)>(p =>
                    {
                        var percentage = (double)p.bytesRead / p.totalBytes * 100;
                        var elapsed = stopwatch.Elapsed;
                        var bytesPerSecond = p.bytesRead > 0 ? p.bytesRead / elapsed.TotalSeconds : 0;
                        var remainingSeconds = bytesPerSecond > 0 ? (p.totalBytes - p.bytesRead) / bytesPerSecond : 0;

                        Dispatch(() =>
                        {
                            DumpProgressPercentage = percentage;
                            DumpProgressBytes = $"Read: {p.bytesRead} / {p.totalBytes} bytes";
                            DumpProgressTime = $"Elapsed: {elapsed.TotalSeconds:F0}s | Remaining: {remainingSeconds:F0}s";
                        });
                    });

                    var options = new MemoryDumpOptions
                    {
                        Address = address,
                        Length = DumpLength,
                        OutputPath = ConfigurationViewModel.DumpsPath,
                        PayloadPath = ConfigurationViewModel.PayloadsPath,
                        Progress = progress,
                        ChannelConfig = new CommunicationChannelConfig
                        {
                            Mode = PlcConnectionViewModel.SelectedCommunicationMode,
                            Host = PlcConnectionViewModel.PlcHost,
                            Port = PlcConnectionViewModel.PlcPort,
                            SerialPort = PlcConnectionViewModel.SelectedSerialPort,
                            BaudRate = PlcConnectionViewModel.SelectedBaudRate,
                            Parity = PlcConnectionViewModel.SelectedParity,
                            StopBits = PlcConnectionViewModel.SelectedStopBits,
                            FlowControl = PlcConnectionViewModel.SelectedFlowControl
                        }
                    };

                    var result = await _memoryDumpHandler.HandleAsync(options, _dumpCancellationTokenSource.Token);

                    if (!result.IsSuccess)
                    {
                        await _dialogService.ShowMessageAsync("Error", result.ErrorMessage ?? "An unknown error occurred during memory dump.");
                    }
                }
                catch (OperationCanceledException)
                {
                    Logging.Log("Memory dump operation was cancelled by user.", LogCategory.Info);
                }
                catch (Exception ex)
                {
                    HandleException(ex);
                }
                finally
                {
                    IsDumpingMemory = false;
                }
            }
            _dumpCancellationTokenSource = null;
        }

        private void CancelDump() => _dumpCancellationTokenSource?.Cancel();

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