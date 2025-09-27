using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Discovers and manages payload files.
    /// </summary>
    public class PayloadDiscoveryService : ViewModelBase, IPayloadDiscoveryService
    {
        private readonly IApplicationStateService _state;
        private readonly IPayloadService _payloadService;
        private readonly IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly ILogger<PayloadDiscoveryService> _logger;
        private CancellationTokenSource? _scanCancellationTokenSource;

        public PayloadDiscoveryService(
            IApplicationStateService applicationStateService,
            IPayloadService payloadService,
            IDialogService dialogService,
            LoggingService loggingService,
            ILogger<PayloadDiscoveryService> logger)
        {
            _state = applicationStateService;
            _payloadService = payloadService;
            _dialogService = dialogService;
            _loggingService = loggingService;
            _logger = logger;
        }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            private set => SetProperty(ref _isScanning, value);
        }

        public ObservableCollection<PayloadInfo> DiscoveredPayloads { get; } = new ObservableCollection<PayloadInfo>();

        public void CancelScan() => _scanCancellationTokenSource?.Cancel();

        public Task ScanPayloadsAsync()
        {
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            return ScanPayloadsInternalAsync(_scanCancellationTokenSource.Token);
        }

        private async Task ScanPayloadsInternalAsync(CancellationToken cancellationToken)
        {
            if (IsScanning || string.IsNullOrWhiteSpace(_state.PayloadsPath))
                return;

            IsScanning = true;

            try
            {
                _logger.LogInformation("Starting payload scan in directory: {PayloadsPath}", _state.PayloadsPath);
                var scanOptions = new PayloadScanOptions
                {
                    IncludeSubdirectories = true,
                    FileExtensions = new[] { ".bin", ".hex", ".elf", ".s", ".c" },
                    ValidatePayloads = true,
                    ExtractMetadata = true,
                    MaxConcurrency = 4,
                    Timeout = TimeSpan.FromMinutes(5)
                };
                var progress = new Progress<PayloadScanProgress>(scanProgress =>
                {
                    _logger.LogDebug("Payload scan progress: {PercentComplete:F1}% - {CurrentDirectory}",
                        scanProgress.PercentComplete, scanProgress.CurrentDirectory);
                });

                var result = await _payloadService.ScanPayloadsAsync(
                    new[] { _state.PayloadsPath },
                    scanOptions,
                    progress,
                    cancellationToken).ConfigureAwait(false);

                if (result.IsSuccess && result.Value != null)
                {
                    var scanResult = result.Value;
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DiscoveredPayloads.Clear();
                        foreach (var discoveredPayload in scanResult.DiscoveredPayloads)
                        {
                            var payloadInfo = new PayloadInfo
                            {
                                Name = discoveredPayload.Name,
                                Type = discoveredPayload.Type.ToString(),
                                RelativePath = System.IO.Path.GetRelativePath(_state.PayloadsPath, discoveredPayload.FilePath),
                                Size = discoveredPayload.Size,
                                LastModified = discoveredPayload.LastModified,
                                Description = discoveredPayload.Description ?? string.Empty
                            };
                            DiscoveredPayloads.Add(payloadInfo);
                        }
                    });

                    _loggingService.Log($"✅ Payload scan completed successfully. Found {scanResult.DiscoveredPayloads.Count} payload files in {scanResult.ScanDuration.TotalSeconds:F1}s", LogCategory.Info);
                }
                else
                {
                    _loggingService.Log($"❌ Payload scan failed: {result.Error.Message}", LogCategory.Error);
                    await _dialogService.ShowMessageAsync("Payload Scan Failed",
                        result.Error.Message ?? "Unknown error occurred during payload scan");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Payload scan was cancelled by user");
                _loggingService.Log("Payload scan was cancelled.", LogCategory.Info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during payload scan");
                _loggingService.Log($"Error scanning payloads: {ex.ToString()}", LogCategory.Error);
                await _dialogService.ShowMessageAsync("Error", $"Error scanning payloads: {ex.Message}");
            }
            finally
            {
                IsScanning = false;
            }
        }
    }
}