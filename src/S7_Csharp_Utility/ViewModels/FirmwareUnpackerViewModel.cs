using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the firmware unpacking functionality.
    /// </summary>
    public class FirmwareUnpackerViewModel : ViewModelBase, IDisposable
    {
        private readonly IDialogService _dialogService;
        private readonly IFirmwareUnpackingService _unpackingService;
        private CancellationTokenSource? _cancellationTokenSource;

        private string _firmwarePath = "";
        public string FirmwarePath
        {
            get => _firmwarePath;
            set => SetProperty(ref _firmwarePath, value);
        }

        private string _extractionPath = "";
        public string ExtractionPath
        {
            get => _extractionPath;
            set => SetProperty(ref _extractionPath, value);
        }

        private string _firmwareMetadataText = "Please select a firmware file.";
        public string FirmwareMetadataText
        {
            get => _firmwareMetadataText;
            set => SetProperty(ref _firmwareMetadataText, value);
        }

        private bool _isUnpackButtonEnabled = false;
        public bool IsUnpackButtonEnabled
        {
            get => _isUnpackButtonEnabled;
            set => SetProperty(ref _isUnpackButtonEnabled, value);
        }

        private bool _isBusy = false;
        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                if (SetProperty(ref _isBusy, value))
                {
                    ((AsyncRelayCommand)SelectFirmwareCommand).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)UnpackFirmwareCommand).RaiseCanExecuteChanged();
                    (CancelCommand as RelayCommand)?.RaiseCanExecuteChanged();
                }
            }
        }

        private double _unpackProgress = 0;
        public double UnpackProgress
        {
            get => _unpackProgress;
            set => SetProperty(ref _unpackProgress, value);
        }

        public ICommand SelectFirmwareCommand { get; }
        public ICommand UnpackFirmwareCommand { get; }
        public ICommand CancelCommand { get; }

        public FirmwareUnpackerViewModel(IDialogService dialogService, IFirmwareUnpackingService unpackingService, string? extractionPath)
        {
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _unpackingService = unpackingService ?? throw new ArgumentNullException(nameof(unpackingService));
            ExtractionPath = extractionPath ?? "";

            SelectFirmwareCommand = new AsyncRelayCommand(SelectFirmwareAsync, _ => !IsBusy, HandleException);
            UnpackFirmwareCommand = new AsyncRelayCommand(UnpackFirmwareAsync, _ => IsUnpackButtonEnabled && !IsBusy, HandleException);
            CancelCommand = new RelayCommand(_ => CancelOperation(), _ => IsBusy);
        }

        private void CancelOperation()
        {
            _cancellationTokenSource?.Cancel();
        }

        private async Task SelectFirmwareAsync()
        {
            IsBusy = true;
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            try
            {
                var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Firmware File", "upd", "UPD Files");
                if (filePath == null) return;
                token.ThrowIfCancellationRequested();

                FirmwarePath = filePath;
                FirmwareMetadataText = "Parsing...";
                IsUnpackButtonEnabled = false;

                var metadata = await _unpackingService.ParseMetadataAsync(FirmwarePath, token);
                token.ThrowIfCancellationRequested();

                var sb = new StringBuilder();
                sb.AppendLine($"Found {metadata.Count} components:");
                foreach (var entry in metadata)
                {
                    sb.AppendLine($" - Name: {entry.Name}, Size: {entry.Size}, CRC: {entry.Crc:X8}");
                }
                FirmwareMetadataText = sb.ToString();
                IsUnpackButtonEnabled = true;
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task UnpackFirmwareAsync()
        {
            if (string.IsNullOrWhiteSpace(FirmwarePath)) return;

            IsBusy = true;
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            try
            {
                string destinationFolder;
                if (!string.IsNullOrWhiteSpace(ExtractionPath))
                {
                    Directory.CreateDirectory(ExtractionPath);
                    destinationFolder = ExtractionPath;
                }
                else
                {
                    var folderPath = await _dialogService.OpenFolderPickerAsync("Select Destination Folder");
                    if (folderPath == null) return;
                    destinationFolder = folderPath;
                }
                token.ThrowIfCancellationRequested();

                string output = Path.Combine(destinationFolder, Path.GetFileName(FirmwarePath) + ".unpacked.bin");

                UnpackProgress = 0;
                var progress = new Progress<double>(p => UnpackProgress = p);

                await _unpackingService.UnpackAsync(FirmwarePath, output, progress, token);
                await _dialogService.ShowMessageAsync("Success", $"Unpacked to: {output}");
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void HandleException(Exception ex)
        {
            if (ex is OperationCanceledException)
            {
                FirmwareMetadataText = "Operation cancelled.";
            }
            else
            {
                FirmwareMetadataText = $"An error occurred: {ex.Message}";
                _dialogService.ShowMessageAsync("Error", $"An unexpected error occurred: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
        }
    }
}