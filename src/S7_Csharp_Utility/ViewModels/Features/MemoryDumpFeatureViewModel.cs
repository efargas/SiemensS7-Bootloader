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
    public class MemoryDumpFeatureViewModel : FeatureViewModelBase
    {
        private readonly IApplicationStateService _state;
        private readonly IMemoryDumpService _memoryDumpService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;

        [Required(ErrorMessage = "Dump address is required")]
        [RegularExpression(@"^0x[0-9a-fA-F]{1,8}$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000). Format: 0x followed by 1-8 hex digits")]
        public string DumpAddress { get => _state.DumpAddress; set => _state.DumpAddress = value; }

        [Range(1, uint.MaxValue, ErrorMessage = "Dump length must be at least 1 byte")]
        [Display(Name = "Dump Length", Description = "Number of bytes to dump from memory")]
        public uint DumpLength { get => _state.DumpLength; set => _state.DumpLength = value; }

        private bool _isDumpingMemory;
        public bool IsDumpingMemory
        {
            get => _isDumpingMemory;
            set
            {
                if (SetProperty(ref _isDumpingMemory, value))
                {
                    if (value) NotifyOperationStarted("MemoryDump");
                    else NotifyOperationCompleted("MemoryDump");
                    ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
                    ((RelayCommand)CancelDumpCommand).RaiseCanExecuteChanged();
                }
            }
        }

        private double _dumpProgressPercentage;
        public double DumpProgressPercentage { get => _dumpProgressPercentage; set => SetProperty(ref _dumpProgressPercentage, value); }

        private long _bytesRead;
        public long BytesRead { get => _bytesRead; set => SetProperty(ref _bytesRead, value); }

        private long _totalBytes;
        public long TotalBytes { get => _totalBytes; set => SetProperty(ref _totalBytes, value); }

        private TimeSpan _elapsed;
        public TimeSpan Elapsed { get => _elapsed; set => SetProperty(ref _elapsed, value); }

        private TimeSpan _estimatedRemaining;
        public TimeSpan EstimatedRemaining { get => _estimatedRemaining; set => SetProperty(ref _estimatedRemaining, value); }

        private double _bytesPerSecond;
        public double BytesPerSecond { get => _bytesPerSecond; set => SetProperty(ref _bytesPerSecond, value); }

        private CancellationTokenSource? _dumpCancellationTokenSource;

        public ICommand DumpMemoryCommand { get; }
        public ICommand CancelDumpCommand { get; }

        public MemoryDumpFeatureViewModel(
            IMemoryDumpService memoryDumpService,
            IDialogService dialogService,
            LoggingService loggingService,
            IApplicationStateService applicationStateService,
            ILogger<MemoryDumpFeatureViewModel> logger) : base(logger, applicationStateService)
        {
            _state = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
            _memoryDumpService = memoryDumpService ?? throw new ArgumentNullException(nameof(memoryDumpService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _loggingService = loggingService ?? throw new ArgumentNullException(nameof(loggingService));

            _state.PropertyChanged += (s, e) => OnPropertyChanged(e.PropertyName);

            DumpMemoryCommand = new AsyncRelayCommand(_ => DumpMemoryAsync(), _ => CanExecuteMemoryDump());
            CancelDumpCommand = new RelayCommand(_ => CancelDump(), _ => CanCancelDump());

            Logger.LogDebug("MemoryDumpFeatureViewModel initialized");
        }

        private bool CanExecuteMemoryDump()
        {
            return !IsDumpingMemory && ApplicationStateService.CanExecuteMemoryDump && !HasErrors;
        }

        private bool CanCancelDump()
        {
            return IsDumpingMemory && _dumpCancellationTokenSource != null;
        }

        private async Task DumpMemoryAsync()
        {
            IsDumpingMemory = true;
            using (_dumpCancellationTokenSource = new CancellationTokenSource())
            {
                try
                {
                    Logger.LogInformation("Starting memory dump operation. Address: {Address}, Length: {Length}", DumpAddress, DumpLength);
                    
                    if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                    {
                        await _dialogService.ShowMessageAsync("Validation Error", "Invalid dump address format. Please use hex format like 0x691E28.");
                        return;
                    }

                    var dumpOptions = new CommandsMemoryDumpOptions
                    {
                        StartAddress = address,
                        Length = DumpLength,
                        OutputPath = ApplicationConfiguration.ResolvePath(_state.DumpsPath, ApplicationConfiguration.GetDefaultDumpsPath()),
                        ChunkSize = 1024,
                        ValidateChecksum = true,
                        CompressOutput = false
                    };

                    var progress = new Progress<MemoryDumpProgress>(progressInfo =>
                    {
                        Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            DumpProgressPercentage = progressInfo.PercentComplete;
                            BytesRead = (long)progressInfo.BytesRead;
                            TotalBytes = (long)progressInfo.TotalBytes;
                            Elapsed = progressInfo.Elapsed;
                            EstimatedRemaining = progressInfo.EstimatedRemaining;
                            BytesPerSecond = progressInfo.Elapsed.TotalSeconds > 0 ? progressInfo.BytesRead / progressInfo.Elapsed.TotalSeconds : 0;
                        });
                    });

                    _loggingService.Log($"Starting memory dump of {DumpLength} bytes from 0x{address:X8}...", LogCategory.Info);
                    var result = await _memoryDumpService.DumpMemoryAsync(dumpOptions, progress, _dumpCancellationTokenSource.Token).ConfigureAwait(false);

                    if (result.IsSuccess && result.Value != null)
                    {
                        var dumpResult = result.Value;
                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                        string outFilename = $"mem_dump_{address:x8}_{address + DumpLength:x8}_{timestamp}.bin";
                        string fullPath = System.IO.Path.Combine(dumpOptions.OutputPath, outFilename);
                        
                        var saveResult = await _memoryDumpService.SaveDumpAsync(dumpResult.Data, fullPath, dumpResult.Metadata, false, _dumpCancellationTokenSource.Token).ConfigureAwait(false);

                        if (saveResult.IsSuccess)
                        {
                            _loggingService.Log($"✅ Successfully dumped {dumpResult.Data.Length} bytes to {fullPath} in {dumpResult.Duration.TotalSeconds:F1}s", LogCategory.Info);
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
                        await _dialogService.ShowMessageAsync("Memory Dump Failed", result.Error.Message ?? "Unknown error occurred during memory dump");
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
                    await _dialogService.ShowMessageAsync("Configuration Error", ex.Message);
                    HandleException(ex, "Memory dump configuration");
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Unexpected error during memory dump");
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

        private void CancelDump()
        {
            Logger.LogInformation("User requested memory dump cancellation");
            _dumpCancellationTokenSource?.Cancel();
        }

        protected override void OnValidationChanged()
        {
            base.OnValidationChanged();
            ((AsyncRelayCommand)DumpMemoryCommand).RaiseCanExecuteChanged();
        }
    }
}