#nullable enable
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
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
    public class MainWindowViewModel(
        LoggingService loggingService,
        SocatLoggerService socatLoggerService,
        IDialogService dialogService,
        ConfigurationService configService,
        IViewService viewService,
        PlcConnectionViewModel plcConnectionViewModel,
        ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
        ConfigurationViewModel configurationViewModel,
        FileCompareViewModel fileCompareViewModel,
        IPlcOperationService plcOperationService,
        IMemoryDumpService memoryDumpService,
        IStagerService stagerService,
        IPayloadService payloadService,
        ILogger<MainWindowViewModel> logger) : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        public PlcConnectionViewModel? PlcConnectionViewModel { get; } = plcConnectionViewModel;
        public ModbusPowerSupplyViewModel? ModbusPowerSupplyViewModel { get; } = modbusPowerSupplyViewModel;
        public ConfigurationViewModel ConfigurationViewModel { get; } = configurationViewModel ?? throw new ArgumentNullException(nameof(configurationViewModel));
        public FileCompareViewModel FileCompareViewModel { get; } = fileCompareViewModel ?? throw new ArgumentNullException(nameof(fileCompareViewModel));
        public LoggingService Logging { get; } = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
        public SocatLoggerService SocatLogging { get; } = socatLoggerService ?? throw new ArgumentNullException(nameof(socatLoggerService));
        
        // Service layer dependencies
        private readonly IPlcOperationService _plcOperationService = plcOperationService ?? throw new ArgumentNullException(nameof(plcOperationService));
        private readonly IMemoryDumpService _memoryDumpService = memoryDumpService ?? throw new ArgumentNullException(nameof(memoryDumpService));
        private readonly IStagerService _stagerService = stagerService ?? throw new ArgumentNullException(nameof(stagerService));
        private readonly IPayloadService _payloadService = payloadService ?? throw new ArgumentNullException(nameof(payloadService));
        private readonly ILogger<MainWindowViewModel> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        private string _dumpAddress = "0x691E28";
        [Required(ErrorMessage = "Dump address is required")]
        [RegularExpression(@"^0x[0-9a-fA-F]{1,8}$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000). Format: 0x followed by 1-8 hex digits")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set 
            { 
                if (SetProperty(ref _dumpAddress, value))
                {
                    ValidateProperty(value, nameof(DumpAddress));
                }
            }
        }

        private uint _dumpLength = 16;
        [Range(1, uint.MaxValue, ErrorMessage = "Dump length must be at least 1 byte")]
        [Display(Name = "Dump Length", Description = "Number of bytes to dump from memory")]
        public uint DumpLength
        {
            get => _dumpLength;
            set 
            { 
                if (SetProperty(ref _dumpLength, value))
                {
                    ValidateProperty(value, nameof(DumpLength));
                }
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

        private string _dumpProgressTime = "Elapsed: 00:00:00 | Remaining: calculating...";
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set => SetProperty(ref _dumpProgressTime, value);
        }

        private string _dumpProgressSpeed = "Speed: 0 B/s";
        public string DumpProgressSpeed
        {
            get => _dumpProgressSpeed;
            set => SetProperty(ref _dumpProgressSpeed, value);
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

        public ICommand LoadProfileCommand { get; }
        public ICommand StartExploitSequenceCommand { get; }
        public ICommand DumpMemoryCommand { get; }
        public ICommand CancelDumpCommand { get; }
        public ICommand ShowProfileManagementCommand { get; }
        public ICommand ShowFirmwareUnpackerCommand { get; }
        public ICommand ShowHexViewerCommand { get; }
        public ICommand SaveConfigurationCommand { get; }
        public ICommand LoadConfigurationCommand { get; }
        public ICommand ExitCommand { get; }
        public ICommand CancelScanCommand { get; }

        private readonly IDialogService _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        public ConfigurationService ConfigService { get; } = configService ?? throw new ArgumentNullException(nameof(configService));

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

        public IViewService ViewService { get; } = viewService ?? throw new ArgumentNullException(nameof(viewService));

        // Primary constructor initialization
        static MainWindowViewModel()
        {
            // Static constructor for any static initialization if needed
        }

        // Instance initialization - called automatically after primary constructor
        private void InitializeCommands()
        {
            // Subscribe to status change events
            if (PlcConnectionViewModel != null)
            {
                PlcConnectionViewModel.SocatStatusChanged += (status) => ((AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
            }
            if (ModbusPowerSupplyViewModel != null)
            {
                ModbusPowerSupplyViewModel.ModbusStatusChanged += (status) => ((AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
            }

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
        /// Determines if the exploit sequence can be executed based on current state.
        /// </summary>
        private bool CanExecuteExploitSequence()
        {
            return PlcConnectionViewModel?.SocatStatus == "Running" 
                && ModbusPowerSupplyViewModel?.ModbusStatus == "Connected" 
                && !IsUploadingStager 
                && !IsDumpingMemory 
                && !IsComparing;
        }

        /// <summary>
        /// Determines if memory dump can be executed based on current state.
        /// </summary>
        private bool CanExecuteMemoryDump()
        {
            return StagerInstalled 
                && !IsUploadingStager 
                && !IsDumpingMemory 
                && !IsComparing;
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
            
            // Update UI state based on connection status
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                ((AsyncRelayCommand)StartExploitSequenceCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
            });
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

        /// <summary>
        /// Executes the exploit sequence using the service layer.
        /// </summary>
        private async Task StartExploitSequenceAsync()
        {
            IsUploadingStager = true;
            
            try
            {
                _logger.LogInformation("Starting exploit sequence execution");
                Logging.Log("[EXPLOIT] Starting exploit sequence...", LogCategory.Info);
                
                // Power cycle if configured
                if (ModbusPowerSupplyViewModel != null)
                {
                    Logging.Log("[POWER] Performing power cycle...", LogCategory.Info);
                    await ModbusPowerSupplyViewModel.PowerCycleAsync(ModbusPowerSupplyViewModel.DelaySeconds);
                    await Task.Delay(50); // Brief delay after power cycle
                }

                // Create channel configuration
                var channelConfig = CreateChannelConfig();
                
                // Create exploit sequence options
                var exploitOptions = new ExploitSequenceOptions
                {
                    ChannelConfig = channelConfig,
                    PayloadPaths = new List<string> { System.IO.Path.Combine(ConfigurationViewModel.PayloadsPath, "stager") },
                    PerformHandshake = true,
                    ValidateSteps = true,
                    TimeoutMs = 300000, // 5 minutes
                    ContinueOnFailure = false
                };

                // Execute exploit sequence through service
                var result = await _plcOperationService.ExecuteExploitSequenceAsync(exploitOptions, CancellationToken.None).ConfigureAwait(false);
                
                if (result.IsSuccess && result.Value != null)
                {
                    StagerInstalled = result.Value.IsSuccess;
                    
                    if (result.Value.IsSuccess)
                    {
                        Logging.Log("✅ Stager installation completed successfully", LogCategory.Info);
                        _logger.LogInformation("Stager installed successfully in {Duration}ms", result.Value.Duration.TotalMilliseconds);
                    }
                    else
                    {
                        Logging.Log($"❌ Stager installation failed: {result.Value.ErrorMessage}", LogCategory.Error);
                        await _dialogService.ShowMessageAsync("Stager Installation Failed", 
                            result.Value.ErrorMessage ?? "Unknown error occurred during stager installation");
                    }
                }
                else
                {
                    Logging.Log($"❌ Exploit sequence failed: {result.Error.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Exploit Sequence Failed",
                    result.Error.Message ?? "Unknown error occurred during exploit sequence");
                }
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Invalid operation during exploit sequence");
                Logging.Log($"[ERROR] Configuration error: {ex.Message}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Configuration Error", ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during exploit sequence");
                Logging.Log($"[ERROR] ❌ Unexpected error during exploit sequence: {ex}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"An error occurred during the exploit sequence: {ex.Message}");
            }
            finally
            {
                IsUploadingStager = false;
            }
        }

        /// <summary>
        /// Executes memory dump using the service layer.
        /// </summary>
        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            using (_dumpCancellationTokenSource = new CancellationTokenSource())
            {
                try
                {
                    _logger.LogInformation("Starting memory dump operation");
                    
                    // Validate dump address
                    if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                    {
                        await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address format. Please use hex format like 0x691E28.");
                        return;
                    }

                    // Create memory dump options
                    var dumpOptions = new S7.Core.Abstractions.Commands.MemoryDumpOptions
                    {
                        StartAddress = address,
                        Length = DumpLength,
                        ChannelConfig = CreateChannelConfig(),
                        OutputPath = ApplicationConfiguration.ResolvePath(ConfigurationViewModel.DumpsPath, ApplicationConfiguration.GetDefaultDumpsPath()),
                        ChunkSize = 1024, // 1KB chunks
                        ValidateChecksum = true,
                        CompressOutput = false
                    };

                    // Create progress reporter for UI updates
                    var progress = new Progress<MemoryDumpProgress>(progressInfo =>
                    {
                        Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            DumpProgressPercentage = progressInfo.PercentComplete;
                            DumpProgressBytes = $"Read: {FormatBytes((long)progressInfo.BytesRead)} / {FormatBytes((long)progressInfo.TotalBytes)}";
                            DumpProgressTime = $"Elapsed: {FormatTime(progressInfo.Elapsed)} | ETA: {FormatTime(progressInfo.EstimatedRemaining)}";
                            
                            // Calculate speed
                            var bytesPerSecond = progressInfo.Elapsed.TotalSeconds > 0 
                                ? progressInfo.BytesRead / progressInfo.Elapsed.TotalSeconds 
                                : 0;
                            DumpProgressSpeed = $"Speed: {FormatBytes((long)bytesPerSecond)}/s";
                        });
                    });

                    Logging.Log($"Starting memory dump of {DumpLength} bytes from 0x{address:X8}...", LogCategory.Info);

                    // Execute memory dump through service
                    var result = await _memoryDumpService.DumpMemoryAsync(dumpOptions, progress, _dumpCancellationTokenSource.Token).ConfigureAwait(false);

                    if (result.IsSuccess && result.Value != null)
                    {
                        var dumpResult = result.Value;
                        
                        // Save the dump to file
                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                        string outFilename = $"mem_dump_{address:x8}_{address + DumpLength:x8}_{timestamp}.bin";
                        string fullPath = System.IO.Path.Combine(dumpOptions.OutputPath, outFilename);
                        
                        var saveResult = await _memoryDumpService.SaveDumpAsync(
                            dumpResult.Data, 
                            fullPath, 
                            dumpResult.Metadata, 
                            false, // Don't compress
                            _dumpCancellationTokenSource.Token).ConfigureAwait(false);

                        if (saveResult.IsSuccess)
                        {
                            Logging.Log($"✅ Successfully dumped {dumpResult.Data.Length} bytes to {fullPath} in {dumpResult.Duration.TotalSeconds:F1}s", LogCategory.Info);
                            _logger.LogInformation("Memory dump completed successfully. File: {FilePath}, Size: {Size} bytes, Duration: {Duration}ms", 
                                fullPath, dumpResult.Data.Length, dumpResult.Duration.TotalMilliseconds);
                        }
                        else
                        {
                            Logging.Log($"❌ Failed to save memory dump: {saveResult.Error.Message}", LogCategory.Error);
                            await _dialogService.ShowMessageAsync("Save Error", $"Failed to save memory dump: {saveResult.Error.Message}");
                        }
                    }
                    else
                    {
                        Logging.Log($"❌ Memory dump failed: {result.Error.Message}", LogCategory.Error);
                        await _dialogService.ShowMessageAsync("Memory Dump Failed", 
                            result.Error.Message ?? "Unknown error occurred during memory dump");
                    }
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Memory dump operation was cancelled by user");
                    Logging.Log("Memory dump operation was cancelled by user.", LogCategory.Info);
                }
                catch (InvalidOperationException ex)
                {
                    _logger.LogError(ex, "Invalid operation during memory dump");
                    Logging.Log($"[ERROR] Configuration error: {ex.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Configuration Error", ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error during memory dump");
                    Logging.Log($"An error occurred during the dump sequence: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"An error occurred during memory dump: {ex.Message}");
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
                    DumpAddress = config.DumpAddress ?? "0x691E28";
                    DumpLength = config.DumpLength;
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
                    DumpAddress = DumpAddress,
                    DumpLength = DumpLength,
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
            
            // Collect all validation errors from all properties
            var propertyNames = new[] { nameof(DumpAddress), nameof(DumpLength) };
            foreach (var propertyName in propertyNames)
            {
                var errors = GetErrors(propertyName);
                if (errors != null)
                {
                    foreach (string error in errors)
                    {
                        allErrors.Add(error);
                    }
                }
            }
            
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
