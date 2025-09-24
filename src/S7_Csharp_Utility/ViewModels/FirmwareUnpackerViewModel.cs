using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.Interfaces;
using S7.Utils;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    public class FirmwareUnpackerViewModel : ViewModelBase, IDisposable
    {
        private readonly S7UpdateUnpacker _unpacker = new S7UpdateUnpacker();
        private readonly IDialogService _dialogService;
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
            set
            {
                if (SetProperty(ref _isUnpackButtonEnabled, value))
                {
                    (UnpackFirmwareCommand as RelayCommand)?.RaiseCanExecuteChanged();
                }
            }
        }

        private bool _isBusy = false;
        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                if (SetProperty(ref _isBusy, value))
                {
                    (SelectFirmwareCommand as RelayCommand)?.RaiseCanExecuteChanged();
                    (UnpackFirmwareCommand as RelayCommand)?.RaiseCanExecuteChanged();
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

        public FirmwareUnpackerViewModel(IDialogService? dialogService, string? extractionPath)
        {
            _dialogService = dialogService ?? new Services.DialogService(); // Fallback
            ExtractionPath = extractionPath ?? "";

            SelectFirmwareCommand = new RelayCommand(_ => SelectFirmware(), _ => !IsBusy);
            UnpackFirmwareCommand = new RelayCommand(_ => UnpackFirmware(), _ => IsUnpackButtonEnabled && !IsBusy);
            CancelCommand = new RelayCommand(_ => CancelOperation(), _ => IsBusy);
        }

        private void SelectFirmware()
        {
            StartOperation(DoSelectFirmwareAsync).FireAndForget(ex => FirmwareMetadataText = $"Error: {ex.Message}");
        }

        private void UnpackFirmware()
        {
            StartOperation(DoUnpackFirmwareAsync).FireAndForget(ex => _dialogService.ShowMessageAsync("Error", $"Error: {ex.Message}"));
        }

        private void CancelOperation()
        {
            _cancellationTokenSource?.Cancel();
        }

        private async Task StartOperation(Func<CancellationToken, Task> operation)
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource = new CancellationTokenSource();

            IsBusy = true;
            try
            {
                await operation(_cancellationTokenSource.Token);
            }
            catch (OperationCanceledException)
            {
                // Operation was cancelled, this is expected.
                FirmwareMetadataText = "Operation cancelled.";
            }
            catch (Exception ex)
            {
                // Handle or re-throw other exceptions
                FirmwareMetadataText = $"An unexpected error occurred: {ex.Message}";
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task DoSelectFirmwareAsync(CancellationToken cancellationToken)
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Firmware File", "upd", "UPD Files");
            if (filePath == null) return;

            FirmwarePath = filePath;
            FirmwareMetadataText = "Parsing...";
            IsUnpackButtonEnabled = false;

            var metadata = await _unpacker.ParseMetadataAsync(FirmwarePath, cancellationToken);

            var sb = new StringBuilder();
            sb.AppendLine($"Found {metadata.Count} components:");
            foreach (var entry in metadata)
            {
                sb.AppendLine($" - Name: {entry.Name}, Size: {entry.Size}, CRC: {entry.Crc:X8}");
            }
            FirmwareMetadataText = sb.ToString();
            IsUnpackButtonEnabled = true;
        }

        private async Task DoUnpackFirmwareAsync(CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(FirmwarePath)) return;

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

            string output = Path.Combine(destinationFolder, Path.GetFileName(FirmwarePath) + ".unpacked.bin");

            UnpackProgress = 0;
            var progress = new Progress<double>(p => UnpackProgress = p);

            await _unpacker.UnpackAsync(FirmwarePath, output, progress, cancellationToken);
            await _dialogService.ShowMessageAsync("Success", $"Unpacked to: {output}");
        }

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
        }
    }
}
