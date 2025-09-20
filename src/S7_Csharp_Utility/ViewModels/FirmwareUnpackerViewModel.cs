using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7.Utils;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    public class FirmwareUnpackerViewModel : ViewModelBase
    {
        private readonly S7UpdateUnpacker _unpacker = new S7UpdateUnpacker();
        private readonly IDialogService _dialogService;

        private string _firmwarePath = "";
        public string FirmwarePath
        {
            get => _firmwarePath;
            set
            {
                _firmwarePath = value;
                OnPropertyChanged();
            }
        }

        private string _extractionPath = "";
        public string ExtractionPath
        {
            get => _extractionPath;
            set
            {
                _extractionPath = value;
                OnPropertyChanged();
            }
        }

        private string _firmwareMetadataText = "Please select a firmware file.";
        public string FirmwareMetadataText
        {
            get => _firmwareMetadataText;
            set
            {
                _firmwareMetadataText = value;
                OnPropertyChanged();
            }
        }

        private bool _isUnpackButtonEnabled = false;
        public bool IsUnpackButtonEnabled
        {
            get => _isUnpackButtonEnabled;
            set
            {
                _isUnpackButtonEnabled = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)UnpackFirmwareCommand).RaiseCanExecuteChanged();
            }
        }

        private bool _isUnpacking = false;
        public bool IsUnpacking
        {
            get => _isUnpacking;
            set
            {
                _isUnpacking = value;
                OnPropertyChanged();
            }
        }

        private double _unpackProgress = 0;
        public double UnpackProgress
        {
            get => _unpackProgress;
            set
            {
                _unpackProgress = value;
                OnPropertyChanged();
            }
        }

        public ICommand SelectFirmwareCommand { get; }
        public ICommand UnpackFirmwareCommand { get; }

        public FirmwareUnpackerViewModel(IDialogService dialogService, string? extractionPath)
        {
            _dialogService = dialogService;
            ExtractionPath = extractionPath ?? "";

            SelectFirmwareCommand = new AsyncRelayCommand(SelectFirmwareAsync);
            UnpackFirmwareCommand = new AsyncRelayCommand(UnpackFirmwareAsync, _ => IsUnpackButtonEnabled);
        }

        private async Task SelectFirmwareAsync()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Firmware File", "upd", "UPD Files");
            if (filePath != null)
            {
                FirmwarePath = filePath;
                FirmwareMetadataText = "Parsing...";
                IsUnpackButtonEnabled = false;

                try
                {
                    var metadata = await Task.Run(() => _unpacker.ParseMetadata(FirmwarePath));
                    var sb = new StringBuilder();
                    sb.AppendLine($"Found {metadata.Count} components:");
                    foreach (var entry in metadata)
                    {
                        sb.AppendLine($" - Name: {entry.Name}, Size: {entry.Size}, CRC: {entry.Crc:X8}");
                    }
                    FirmwareMetadataText = sb.ToString();
                    IsUnpackButtonEnabled = true;
                }
                catch (System.Exception ex)
                {
                    FirmwareMetadataText = $"Error: {ex.Message}";
                }
            }
        }

        private async Task UnpackFirmwareAsync()
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

            IsUnpacking = true;
            UnpackProgress = 0;
            var progress = new Progress<double>(p => UnpackProgress = p);

            try
            {
                await Task.Run(() => _unpacker.Unpack(FirmwarePath, output, progress));
                await _dialogService.ShowMessageAsync("Success", $"Unpacked to: {output}");
            }
            catch (System.Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error: {ex.Message}");
            }
            finally
            {
                IsUnpacking = false;
            }
        }
    }
}
