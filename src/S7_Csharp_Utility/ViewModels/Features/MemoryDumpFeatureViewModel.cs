#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using S7_Csharp_Utility.Models;
using CommandsMemoryDumpOptions = S7.Core.Abstractions.Commands.MemoryDumpOptions;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.ViewModels.Features
{
    /// <summary>
    /// Feature ViewModel responsible for memory dump operations.
    /// Handles memory dump configuration, execution, progress tracking, and cancellation.
    /// </summary>
    public class MemoryDumpFeatureViewModel : FeatureViewModelBase
    {
        private readonly IMemoryDumpService _memoryDumpService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly ConfigurationViewModel _configurationViewModel;

        private string _dumpAddress = "0x691E28";
        /// <summary>
        /// Gets or sets the memory address to dump from.
        /// </summary>
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
        /// <summary>
        /// Gets or sets the number of bytes to dump from memory.
        /// </summary>
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

        private bool _isDumpingMemory;
        /// <summary>
        /// Gets or sets a value indicating whether a memory dump operation is currently in progress.
        /// </summary>
        public bool IsDumpingMemory
        {
            get => _isDumpingMemory;
            set
            {
                if (SetProperty(ref _isDumpingMemory, value))
                {
                    // Notify application state service about operation state change
                    if (value)
                    {
                        NotifyOperationStarted("MemoryDump");
                    }
                    else
                    {
                        NotifyOperationCompleted("MemoryDump");
                    }

                    // Update command states
                    ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                    ((RelayCommand)CancelDumpCommand).RaiseCanExecuteChanged();
                }
            }
        }

        private double _dumpProgressPercentage;
        /// <summary>
        /// Gets or sets the current progress percentage of the memory dump operation.
        /// </summary>
        public double DumpProgressPercentage
        {
            get => _dumpProgressPercentage;
            set => SetProperty(ref _dumpProgressPercentage, value);
        }

        private string _dumpProgressBytes = "Read: 0 / 0 bytes";
        /// <summary>
        /// Gets or sets the progress text showing bytes read vs total bytes.
        /// </summary>
        public string DumpProgressBytes
        {
            get => _dumpProgressBytes;
            set => SetProperty(ref _dumpProgressBytes, value);
        }

        private string _dumpProgressTime = "Elapsed: 00:00:00 | Remaining: calculating...";
        /// <summary>
        /// Gets or sets the progress text showing elapsed and estimated remaining time.
        /// </summary>
        public string DumpProgressTime
        {
            get => _dumpProgressTime;
            set => SetProperty(ref _dumpProgressTime, value);
        }

        private string _dumpProgressSpeed = "Speed: 0 B/s";
        /// <summary>
        /// Gets or sets the progress text showing current transfer speed.
        /// </summary>
        public string DumpProgressSpeed
        {
            get => _dumpProgressSpeed;
            set => SetProperty(ref _dumpProgressSpeed, value);
        }

        private CancellationTokenSource? _dumpCancellationTokenSource;

        /// <summary>
        /// Gets the command to start a memory dump operation.
        /// </summary>
        public ICommand DumpMemoryCommand { get; }

        /// <summary>
        /// Gets the command to cancel an ongoing memory dump operation.
        /// </summary>
        public ICommand CancelDumpCommand { get; }

        /// <summary>
        /// Initializes a new instance of the MemoryDumpFeatureViewModel class.
        /// </summary>
        /// <param name="memoryDumpService">The memory dump service for executing dump operations.</param>
        /// <param name="dialogService">The dialog service for user interactions.</param>
        /// <param name="loggingService">The logging service for operation logging.</param>
        /// <param name="configurationViewModel">The configuration view model for accessing paths.</param>
        /// <param name="applicationStateService">The application state service for state coordination.</param>
        /// <param name="logger">The logger instance for this feature ViewModel.</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        public MemoryDumpFeatureViewModel(
            IMemoryDumpService memoryDumpService,
            IDialogService dialogService,
            LoggingService loggingService,
            ConfigurationViewModel configurationViewModel,
            IApplicationStateService applicationStateService,
            ILogger<MemoryDumpFeatureViewModel> logger) : base(logger, applicationStateService)
        {
            _memoryDumpService = memoryDumpService ?? throw new ArgumentNullException(nameof(memoryDumpService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _loggingService = loggingService ?? throw new ArgumentNullException(nameof(loggingService));
            _configurationViewModel = configurationViewModel ?? throw new ArgumentNullException(nameof(configurationViewModel));

            // Initialize commands
            DumpMemoryCommand = new AsyncRelayCommand(_ => DumpMemoryAsync(), _ => CanExecuteMemoryDump());
            CancelDumpCommand = new RelayCommand(_ => CancelDump(), _ => CanCancelDump());

            Logger.LogDebug("MemoryDumpFeatureViewModel initialized");
        }

        /// <summary>
        /// Determines if memory dump can be executed based on current state.
        /// </summary>
        /// <returns>True if memory dump can be executed; otherwise, false.</returns>
        private bool CanExecuteMemoryDump()
        {
            return !IsDumpingMemory && 
                   ApplicationStateService.CanExecuteMemoryDump && 
                   !HasErrors;
        }

        /// <summary>
        /// Determines if memory dump can be cancelled based on current state.
        /// </summary>
        /// <returns>True if memory dump can be cancelled; otherwise, false.</returns>
        private bool CanCancelDump()
        {
            return IsDumpingMemory && _dumpCancellationTokenSource != null;
        }

        /// <summary>
        /// Executes memory dump using the service layer with comprehensive progress reporting.
        /// </summary>
        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            using (_dumpCancellationTokenSource = new CancellationTokenSource())
            {
                try
                {
                    Logger.LogInformation("Starting memory dump operation. Address: {Address}, Length: {Length}", 
                        DumpAddress, DumpLength);
                    
                    // Validate dump address
                    if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                    {
                        await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address format. Please use hex format like 0x691E28.");
                        return;
                    }

                    // Create memory dump options
                    var dumpOptions = new CommandsMemoryDumpOptions
                    {
                        StartAddress = address,
                        Length = DumpLength,
                        OutputPath = ApplicationConfiguration.ResolvePath(_configurationViewModel.DumpsPath, ApplicationConfiguration.GetDefaultDumpsPath()),
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

                    _loggingService.Log($"Starting memory dump of {DumpLength} bytes from 0x{address:X8}...", LogCategory.Info);

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
                            _loggingService.Log($"✅ Successfully dumped {dumpResult.Data.Length} bytes to {fullPath} in {dumpResult.Duration.TotalSeconds:F1}s", LogCategory.Info);
                            Logger.LogInformation("Memory dump completed successfully. File: {FilePath}, Size: {Size} bytes, Duration: {Duration}ms", 
                                fullPath, dumpResult.Data.Length, dumpResult.Duration.TotalMilliseconds);
                        }
                        else
                        {
                            _loggingService.Log($"❌ Failed to save memory dump: {saveResult.Error.Message}", LogCategory.Error);
                            await _dialogService.ShowMessageAsync("Save Error", $"Failed to save memory dump: {saveResult.Error.Message}");
                        }
                    }
                    else
                    {
                        _loggingService.Log($"❌ Memory dump failed: {result.Error.Message}", LogCategory.Error);
                        await _dialogService.ShowMessageAsync("Memory Dump Failed", 
                            result.Error.Message ?? "Unknown error occurred during memory dump");
                    }
                }
                catch (OperationCanceledException)
                {
                    Logger.LogInformation("Memory dump operation was cancelled by user");
                    _loggingService.Log("Memory dump operation was cancelled by user.", LogCategory.Info);
                }
                catch (InvalidOperationException ex)
                {
                    Logger.LogError(ex, "Invalid operation during memory dump");
                    _loggingService.Log($"[ERROR] Configuration error: {ex.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Configuration Error", ex.Message);
                    HandleException(ex, "Memory dump configuration");
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Unexpected error during memory dump");
                    _loggingService.Log($"An error occurred during the dump sequence: {ex}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Error", $"An error occurred during memory dump: {ex.Message}");
                    HandleException(ex, "Memory dump execution");
                }
                finally
                {
                    IsDumpingMemory = false;
                }
            }
            _dumpCancellationTokenSource = null;
        }

        /// <summary>
        /// Cancels the ongoing memory dump operation.
        /// </summary>
        private void CancelDump()
        {
            Logger.LogInformation("User requested memory dump cancellation");
            _dumpCancellationTokenSource?.Cancel();
        }

        /// <summary>
        /// Formats bytes into human-readable format (B, KB, MB, GB).
        /// </summary>
        /// <param name="bytes">The number of bytes to format.</param>
        /// <returns>A formatted string representing the byte size.</returns>
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
        /// <param name="timeSpan">The TimeSpan to format.</param>
        /// <returns>A formatted string representing the time span.</returns>
        private static string FormatTime(TimeSpan timeSpan)
        {
            return $"{(int)timeSpan.TotalHours:D2}:{timeSpan.Minutes:D2}:{timeSpan.Seconds:D2}";
        }

        /// <summary>
        /// Called when validation state changes. Updates command states based on validation.
        /// </summary>
        protected override void OnValidationChanged()
        {
            base.OnValidationChanged();
            
            // Update command states when validation changes
            ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
        }
    }
}