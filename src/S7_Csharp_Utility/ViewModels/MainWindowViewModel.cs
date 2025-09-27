#nullable enable
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.ViewModels.Features;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using Avalonia.Threading;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Interfaces;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using Microsoft.Extensions.Logging;
using S7.Net;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        /// <summary>
        /// Initializes a new instance of the MainWindowViewModel class.
        /// </summary>
        public MainWindowViewModel(
            LoggingService loggingService,
            SocatLoggerService socatLoggerService,
            IDialogService dialogService,
            ConfigurationService configService,
            IViewService viewService,
            PlcConnectionViewModel plcConnectionViewModel,
            ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
            ConfigurationViewModel configurationViewModel,
            FileCompareViewModel fileCompareViewModel,
            MemoryDumpFeatureViewModel memoryDumpFeatureViewModel,
            ExploitSequenceFeatureViewModel exploitSequenceFeatureViewModel,
            IPlcOperationService plcOperationService,
            IMemoryDumpService memoryDumpService,
            IStagerService stagerService,
            IPayloadService payloadService,
            ILogger<MainWindowViewModel> logger)
        {
            // Initialize properties
            PlcConnectionViewModel = plcConnectionViewModel;
            ModbusPowerSupplyViewModel = modbusPowerSupplyViewModel;
            ConfigurationViewModel = configurationViewModel ?? throw new ArgumentNullException(nameof(configurationViewModel));
            FileCompareViewModel = fileCompareViewModel ?? throw new ArgumentNullException(nameof(fileCompareViewModel));
            MemoryDumpFeature = memoryDumpFeatureViewModel ?? throw new ArgumentNullException(nameof(memoryDumpFeatureViewModel));
            ExploitSequenceFeature = exploitSequenceFeatureViewModel ?? throw new ArgumentNullException(nameof(exploitSequenceFeatureViewModel));
            Logging = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
            SocatLogging = socatLoggerService ?? throw new ArgumentNullException(nameof(socatLoggerService));
            ViewService = viewService ?? throw new ArgumentNullException(nameof(viewService));
            ConfigService = configService ?? throw new ArgumentNullException(nameof(configService));

            // Initialize service dependencies
            _plcOperationService = plcOperationService ?? throw new ArgumentNullException(nameof(plcOperationService));
            _memoryDumpService = memoryDumpService ?? throw new ArgumentNullException(nameof(memoryDumpService));
            _stagerService = stagerService ?? throw new ArgumentNullException(nameof(stagerService));
            _payloadService = payloadService ?? throw new ArgumentNullException(nameof(payloadService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));

            // Initialize commands and start services
            InitializeCommands();
        }

        public PlcConnectionViewModel? PlcConnectionViewModel { get; private set; }
        public ModbusPowerSupplyViewModel? ModbusPowerSupplyViewModel { get; private set; }
        public ConfigurationViewModel ConfigurationViewModel { get; private set; }
        public FileCompareViewModel FileCompareViewModel { get; private set; }
        public MemoryDumpFeatureViewModel MemoryDumpFeature { get; private set; }
        public ExploitSequenceFeatureViewModel ExploitSequenceFeature { get; private set; }
        public LoggingService Logging { get; private set; }
        public SocatLoggerService SocatLogging { get; private set; }
        public IViewService ViewService { get; private set; }
        public ConfigurationService ConfigService { get; private set; }
        
        // Service layer dependencies
        private readonly IPlcOperationService _plcOperationService;
        private readonly IMemoryDumpService _memoryDumpService;
        private readonly IStagerService _stagerService;
        private readonly IPayloadService _payloadService;
        private readonly ILogger<MainWindowViewModel> _logger;
        private readonly IDialogService _dialogService;

        
        private bool _isComparing;
        public bool IsComparing
        {
            get => _isComparing;
            set
            {
                _isComparing = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<PayloadInfo>();

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        private string _validationSummary = string.Empty;
        public string ValidationSummary
        {
            get => _validationSummary;
            set => SetProperty(ref _validationSummary, value);
        }

        private bool _hasValidationErrors;
        public bool HasValidationErrors
        {
            get => _hasValidationErrors;
            set => SetProperty(ref _hasValidationErrors, value);
        }

        public ICommand LoadProfileCommand { get; private set; } = null!;
        public ICommand ShowProfileManagementCommand { get; private set; } = null!;
        public ICommand ShowFirmwareUnpackerCommand { get; private set; } = null!;
                public ICommand SaveConfigurationCommand { get; private set; } = null!;
        public ICommand LoadConfigurationCommand { get; private set; } = null!;
        public ICommand ExitCommand { get; private set; } = null!;
        public ICommand CancelScanCommand { get; private set; } = null!;

        
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
                    MemoryDumpFeature.DumpAddress = _selectedMemoryRegion.Address;
                    MemoryDumpFeature.DumpLength = _selectedMemoryRegion.Size;
                }
            }
        }

        
        // Primary constructor initialization
        static MainWindowViewModel()
        {
            // Static constructor for any static initialization if needed
        }

        // Instance initialization - called automatically after primary constructor
        private void InitializeCommands()
        {
            // Initialize commands
            LoadProfileCommand = new AsyncRelayCommand(async _ => await LoadProfileAsync().ConfigureAwait(false), _ => true);
            ShowProfileManagementCommand = new RelayCommand(_ => ShowProfileManagement(), _ => true);
            ShowFirmwareUnpackerCommand = new RelayCommand(_ => ShowFirmwareUnpacker(), _ => true);
                        SaveConfigurationCommand = new AsyncRelayCommand(async _ => await SaveConfigurationAsync().ConfigureAwait(false), _ => true);
            LoadConfigurationCommand = new AsyncRelayCommand(async _ => await LoadConfigurationAsync().ConfigureAwait(false), _ => true);
            ExitCommand = new RelayCommand(_ => Exit(), _ => true);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), _ => !IsScanning);

            // Subscribe to service events
            _plcOperationService.ConnectionStatusChanged += OnPlcConnectionStatusChanged;
            _plcOperationService.OperationCompleted += OnPlcOperationCompleted;

            StartScanPayloads();
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in MainWindowViewModel");
            Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        
        /// <summary>
        /// Creates a communication channel configuration from the current UI settings.
        /// </summary>
        private CommunicationChannelConfig CreateChannelConfig()
        {
            if (PlcConnectionViewModel?.SelectedCommunicationMode == "TCP (socat)")
            {
                return new CommunicationChannelConfig
                {
                    Mode = "TCP",
                    Host = PlcConnectionViewModel.PlcHost ?? "localhost",
                    Port = PlcConnectionViewModel.PlcPort,
                    Timeout = TimeSpan.FromSeconds(30)
                };
            }
            else if (PlcConnectionViewModel?.SelectedCommunicationMode == "Serial" && PlcConnectionViewModel.SelectedSerialPort != null)
            {
                return new CommunicationChannelConfig
                {
                    Mode = "Serial",
                    SerialPort = PlcConnectionViewModel.SelectedSerialPort,
                    BaudRate = PlcConnectionViewModel.SelectedBaudRate,
                    Parity = PlcConnectionViewModel.SelectedParity.ToString(),
                    StopBits = PlcConnectionViewModel.SelectedStopBits.ToString(),
                    FlowControl = PlcConnectionViewModel.SelectedFlowControl.ToString(),
                    Timeout = TimeSpan.FromSeconds(30)
                };
            }

            throw new InvalidOperationException("No valid communication channel configuration available");
        }

        /// <summary>
        /// Event handler for PLC connection status changes.
        /// </summary>
        private void OnPlcConnectionStatusChanged(object? sender, PlcConnectionStatusChangedEventArgs e)
        {
            _logger.LogInformation("PLC connection status changed from {PreviousStatus} to {CurrentStatus}", 
                e.PreviousStatus, e.CurrentStatus);
        }

        /// <summary>
        /// Event handler for PLC operation completion.
        /// </summary>
        private void OnPlcOperationCompleted(object? sender, PlcOperationCompletedEventArgs e)
        {
            _logger.LogInformation("PLC operation '{OperationName}' completed. Success: {IsSuccess}, Duration: {Duration}ms", 
                e.OperationName, e.IsSuccess, e.Duration.TotalMilliseconds);
            
            if (!e.IsSuccess && !string.IsNullOrEmpty(e.ErrorMessage))
            {
                Logging.Log($"PLC operation '{e.OperationName}' failed: {e.ErrorMessage}", LogCategory.Error);
            }
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

        
        
        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = await ConfigService.LoadConfigurationAsync(path);
                if (config != null)
                {
                    if (PlcConnectionViewModel != null)
                    {
                        PlcConnectionViewModel.PlcHost = config.PlcHost ?? "localhost";
                        PlcConnectionViewModel.PlcPort = config.PlcPort;
                    }
                    if (ModbusPowerSupplyViewModel != null)
                    {
                        ModbusPowerSupplyViewModel.ModbusHost = config.ModbusHost ?? "localhost";
                        ModbusPowerSupplyViewModel.ModbusPort = config.ModbusPort;
                        ModbusPowerSupplyViewModel.ModbusCoil = config.ModbusCoil;
                        ModbusPowerSupplyViewModel.DelaySeconds = config.DelaySeconds;
                    }
                    MemoryDumpFeature.DumpAddress = config.DumpAddress ?? "0x691E28";
                    MemoryDumpFeature.DumpLength = config.DumpLength;
                    FileCompareViewModel.CompareFolder = config.CompareFolder ?? string.Empty;
                    FileCompareViewModel.CompareFile1 = config.CompareFile1 ?? string.Empty;
                    FileCompareViewModel.CompareFile2 = config.CompareFile2 ?? string.Empty;
                    if (PlcConnectionViewModel != null)
                    {
                        PlcConnectionViewModel.SelectedSerialPort = config.SelectedSerialPort ?? string.Empty;
                        PlcConnectionViewModel.SocatTcpPort = config.SocatTcpPort;
                        PlcConnectionViewModel.SelectedBaudRate = config.SelectedBaudRate;
                        PlcConnectionViewModel.SelectedParity = config.SelectedParity;
                        PlcConnectionViewModel.SelectedStopBits = config.SelectedStopBits;
                        PlcConnectionViewModel.SelectedFlowControl = config.SelectedFlowControl;
                        PlcConnectionViewModel.SocatVerbose = config.SocatVerbose;
                        PlcConnectionViewModel.SocatHexDump = config.SocatHexDump;
                        PlcConnectionViewModel.SocatBlockSize = config.SocatBlockSize;
                    }
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

        private async Task LoadConfigurationAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Configuration Files").ConfigureAwait(false);
            if (path != null)
            {
                try
                {
                    var config = await ConfigService.LoadConfigurationAsync(path);
                    if (config != null)
                    {
                        // Apply loaded configuration to all view models
                        if (PlcConnectionViewModel != null)
                        {
                            PlcConnectionViewModel.PlcHost = config.PlcHost ?? "localhost";
                            PlcConnectionViewModel.PlcPort = config.PlcPort;
                        }
                        if (ModbusPowerSupplyViewModel != null)
                        {
                            ModbusPowerSupplyViewModel.ModbusHost = config.ModbusHost ?? "localhost";
                            ModbusPowerSupplyViewModel.ModbusPort = config.ModbusPort;
                            ModbusPowerSupplyViewModel.ModbusCoil = config.ModbusCoil;
                            ModbusPowerSupplyViewModel.DelaySeconds = config.DelaySeconds;
                        }
                        MemoryDumpFeature.DumpAddress = config.DumpAddress ?? "0x691E28";
                        MemoryDumpFeature.DumpLength = config.DumpLength;
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

                        // Update logs path
                        string resolvedLogsPath = ApplicationConfiguration.ResolvePath(ConfigurationViewModel.LogsPath, ApplicationConfiguration.GetDefaultLogsPath());
                        Logging.UpdateLogsPath(resolvedLogsPath);
                        SocatLogging.UpdateLogsPath(resolvedLogsPath);

                        Logging.Log($"Configuration loaded successfully from {path}.", LogCategory.Info);
                        await _dialogService.ShowMessageAsync("Success", "Configuration loaded successfully!");
                    }
                    else
                    {
                        await _dialogService.ShowMessageAsync("Error", "Failed to load configuration file. The file may be corrupted or in an invalid format.");
                    }
                }
                catch (Exception ex)
                {
                    Logging.Log($"Error loading configuration from {path}: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Error loading configuration: {ex.Message}");
                }
            }
        }

        private async Task SaveConfigurationAsync()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Configuration Files").ConfigureAwait(false);
            if (path != null)
            {
                try
                {
                    var config = new ApplicationConfiguration
                    {
                        PlcHost = PlcConnectionViewModel?.PlcHost,
                        PlcPort = PlcConnectionViewModel?.PlcPort ?? 0,
                        ModbusHost = ModbusPowerSupplyViewModel?.ModbusHost,
                        ModbusPort = ModbusPowerSupplyViewModel?.ModbusPort ?? 0,
                        ModbusCoil = ModbusPowerSupplyViewModel?.ModbusCoil ?? 0,
                        DelaySeconds = ModbusPowerSupplyViewModel?.DelaySeconds ?? 0,
                        DumpAddress = MemoryDumpFeature.DumpAddress,
                        DumpLength = MemoryDumpFeature.DumpLength,
                        CompareFolder = FileCompareViewModel.CompareFolder,
                        CompareFile1 = FileCompareViewModel.CompareFile1,
                        CompareFile2 = FileCompareViewModel.CompareFile2,
                        SelectedSerialPort = PlcConnectionViewModel?.SelectedSerialPort,
                        SocatTcpPort = PlcConnectionViewModel?.SocatTcpPort ?? 0,
                        SelectedBaudRate = PlcConnectionViewModel?.SelectedBaudRate ?? 0,
                        SelectedParity = PlcConnectionViewModel?.SelectedParity ?? System.IO.Ports.Parity.None,
                        SelectedStopBits = PlcConnectionViewModel?.SelectedStopBits ?? System.IO.Ports.StopBits.One,
                        SelectedFlowControl = PlcConnectionViewModel?.SelectedFlowControl ?? System.IO.Ports.Handshake.None,
                        SocatVerbose = PlcConnectionViewModel?.SocatVerbose ?? false,
                        SocatHexDump = PlcConnectionViewModel?.SocatHexDump ?? false,
                        SocatBlockSize = PlcConnectionViewModel?.SocatBlockSize ?? 0,
                        PayloadsPath = ConfigurationViewModel.PayloadsPath,
                        DumpsPath = ConfigurationViewModel.DumpsPath,
                        LogsPath = ConfigurationViewModel.LogsPath,
                        ExtractionPath = ConfigurationViewModel.ExtractionPath
                    };
                    await ConfigService.SaveConfigurationAsync(config, path);
                    Logging.Log($"Configuration saved successfully to {path}.", LogCategory.Info);
                    await _dialogService.ShowMessageAsync("Success", "Configuration saved successfully!");
                }
                catch (Exception ex)
                {
                    Logging.Log($"Error saving configuration to {path}: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"Error saving configuration: {ex.Message}");
                }
            }
        }

        public async Task SaveConfigurationOnExit()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = new ApplicationConfiguration
                {
                    PlcHost = PlcConnectionViewModel?.PlcHost,
                    PlcPort = PlcConnectionViewModel?.PlcPort ?? 0,
                    ModbusHost = ModbusPowerSupplyViewModel?.ModbusHost,
                    ModbusPort = ModbusPowerSupplyViewModel?.ModbusPort ?? 0,
                    ModbusCoil = ModbusPowerSupplyViewModel?.ModbusCoil ?? 0,
                    DelaySeconds = ModbusPowerSupplyViewModel?.DelaySeconds ?? 0,
                    DumpAddress = MemoryDumpFeature.DumpAddress,
                    DumpLength = MemoryDumpFeature.DumpLength,
                    CompareFolder = FileCompareViewModel.CompareFolder,
                    CompareFile1 = FileCompareViewModel.CompareFile1,
                    CompareFile2 = FileCompareViewModel.CompareFile2,
                    SelectedSerialPort = PlcConnectionViewModel?.SelectedSerialPort,
                    SocatTcpPort = PlcConnectionViewModel?.SocatTcpPort ?? 0,
                    SelectedBaudRate = PlcConnectionViewModel?.SelectedBaudRate ?? 0,
                    SelectedParity = PlcConnectionViewModel?.SelectedParity ?? System.IO.Ports.Parity.None,
                    SelectedStopBits = PlcConnectionViewModel?.SelectedStopBits ?? System.IO.Ports.StopBits.One,
                    SelectedFlowControl = PlcConnectionViewModel?.SelectedFlowControl ?? System.IO.Ports.Handshake.None,
                    SocatVerbose = PlcConnectionViewModel?.SocatVerbose ?? false,
                    SocatHexDump = PlcConnectionViewModel?.SocatHexDump ?? false,
                    SocatBlockSize = PlcConnectionViewModel?.SocatBlockSize ?? 0,
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

        /// <summary>
        /// Formats bytes into human-readable format (B, KB, MB, GB).
        /// </summary>
        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F1} GB";
        }

        /// <summary>
        /// Formats TimeSpan into HH:MM:SS format.
        /// </summary>
        private static string FormatTime(TimeSpan timeSpan)
        {
            return $"{(int)timeSpan.TotalHours:D2}:{timeSpan.Minutes:D2}:{timeSpan.Seconds:D2}";
        }

        /// <summary>
        /// Updates validation summary when validation state changes.
        /// </summary>
        protected override void OnValidationChanged()
        {
            base.OnValidationChanged();
            
            var allErrors = new List<string>();
            
            // MainWindowViewModel no longer has validation properties - they've been moved to feature ViewModels
            // This method is kept for potential future validation needs
            
            // Update validation summary properties
            HasValidationErrors = allErrors.Any();
            ValidationSummary = HasValidationErrors 
                ? $"⚠️ {allErrors.Count} validation error(s): {string.Join("; ", allErrors)}"
                : string.Empty;
        }

        private void StartScanPayloads()
        {
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            ScanPayloadsAsync(_scanCancellationTokenSource.Token).FireAndForget(ex => Logging.Log($"Error during payload scan: {ex.Message}", LogCategory.Error));
        }

        /// <summary>
        /// Scans for payloads using the service layer with thread-safe UI updates.
        /// </summary>
        private async Task ScanPayloadsAsync(CancellationToken cancellationToken)
        {
            if (IsScanning || string.IsNullOrWhiteSpace(ConfigurationViewModel.PayloadsPath))
                return;

            IsScanning = true;
            ((RelayCommand)CancelScanCommand).RaiseCanExecuteChanged();

            try
            {
                _logger.LogInformation("Starting payload scan in directory: {PayloadsPath}", ConfigurationViewModel.PayloadsPath);
                
                // Create scan options
                var scanOptions = new PayloadScanOptions
                {
                    IncludeSubdirectories = true,
                    FileExtensions = new[] { ".bin", ".hex", ".elf", ".s", ".c" },
                    ValidatePayloads = true,
                    ExtractMetadata = true,
                    MaxConcurrency = 4,
                    Timeout = TimeSpan.FromMinutes(5)
                };

                // Create progress reporter for scan updates
                var progress = new Progress<PayloadScanProgress>(scanProgress =>
                {
                    _logger.LogDebug("Payload scan progress: {PercentComplete:F1}% - {CurrentDirectory}", 
                        scanProgress.PercentComplete, scanProgress.CurrentDirectory);
                });

                // Execute payload scan through service
                var result = await _payloadService.ScanPayloadsAsync(
                    new[] { ConfigurationViewModel.PayloadsPath }, 
                    scanOptions, 
                    progress, 
                    cancellationToken).ConfigureAwait(false);

                if (result.IsSuccess && result.Value != null)
                {
                    var scanResult = result.Value;
                    
                    // Update UI on UI thread with thread-safe collection updates
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DiscoveredPayloads.Clear();
                        
                        foreach (var discoveredPayload in scanResult.DiscoveredPayloads)
                        {
                            // Convert service model to UI model
                            var payloadInfo = new PayloadInfo
                            {
                                Name = discoveredPayload.Name,
                                Type = discoveredPayload.Type.ToString(),
                                RelativePath = System.IO.Path.GetRelativePath(ConfigurationViewModel.PayloadsPath, discoveredPayload.FilePath),
                                Size = discoveredPayload.Size,
                                LastModified = discoveredPayload.LastModified,
                                Description = discoveredPayload.Description ?? string.Empty
                            };
                            
                            DiscoveredPayloads.Add(payloadInfo);
                        }
                    });

                    Logging.Log($"✅ Payload scan completed successfully. Found {scanResult.DiscoveredPayloads.Count} payload files in {scanResult.ScanDuration.TotalSeconds:F1}s", LogCategory.Info);
                    _logger.LogInformation("Payload scan completed. Found {PayloadCount} payloads, scanned {DirectoriesScanned} directories, {FilesScanned} files in {Duration}ms", 
                        scanResult.DiscoveredPayloads.Count, scanResult.DirectoriesScanned, scanResult.FilesScanned, scanResult.ScanDuration.TotalMilliseconds);

                    // Log individual payloads for debugging
                    foreach (var payload in scanResult.DiscoveredPayloads)
                    {
                        Logging.Log($"  - {payload.Type}: {System.IO.Path.GetFileName(payload.FilePath)} ({FormatBytes(payload.Size)})", LogCategory.Debug);
                    }
                }
                else
                {
                    Logging.Log($"❌ Payload scan failed: {result.Error.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Payload Scan Failed", 
                        result.Error.Message ?? "Unknown error occurred during payload scan");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Payload scan was cancelled by user");
                Logging.Log("Payload scan was cancelled.", LogCategory.Info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during payload scan");
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
