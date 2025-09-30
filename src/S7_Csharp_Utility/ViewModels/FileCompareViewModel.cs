#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the file comparison.
    /// </summary>
    public class FileCompareViewModel : ViewModelBase
    {
        private readonly IDialogService _dialogService;
        private readonly ILogger<FileCompareViewModel> _logger;
        private readonly IViewService _viewService;
        private readonly IFileComparisonService _fileComparisonService;

        private bool _isComparing;
        public bool IsComparing
        {
            get => _isComparing;
            set
            {
                if (SetProperty(ref _isComparing, value))
                {
                    ((AsyncRelayCommand)BrowseCompareFolderCommand).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)BrowseCompareFile1Command).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)BrowseCompareFile2Command).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)CompareDumpsCommand).RaiseCanExecuteChanged();
                    ((AsyncRelayCommand)CompareTwoFilesCommand).RaiseCanExecuteChanged();
                }
            }
        }

        private string _compareFolder = string.Empty;
        public string CompareFolder
        {
            get => _compareFolder;
            set
            {
                if (SetProperty(ref _compareFolder, value))
                {
                    ((AsyncRelayCommand)CompareDumpsCommand).RaiseCanExecuteChanged();
                }
            }
        }

        private string _compareFile1 = string.Empty;
        public string CompareFile1
        {
            get => _compareFile1;
            set
            {
                if (SetProperty(ref _compareFile1, value))
                {
                    ((AsyncRelayCommand)CompareTwoFilesCommand).RaiseCanExecuteChanged();
                }
            }
        }

        private string _compareFile2 = string.Empty;
        public string CompareFile2
        {
            get => _compareFile2;
            set
            {
                if (SetProperty(ref _compareFile2, value))
                {
                    ((AsyncRelayCommand)CompareTwoFilesCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public ICommand BrowseCompareFolderCommand { get; }
        public ICommand BrowseCompareFile1Command { get; }
        public ICommand BrowseCompareFile2Command { get; }
        public ICommand CompareDumpsCommand { get; }
        public ICommand CompareTwoFilesCommand { get; }

        public FileCompareViewModel(
            IDialogService dialogService,
            ILogger<FileCompareViewModel> logger,
            IViewService viewService,
            IFileComparisonService fileComparisonService)
        {
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _viewService = viewService ?? throw new ArgumentNullException(nameof(viewService));
            _fileComparisonService = fileComparisonService ?? throw new ArgumentNullException(nameof(fileComparisonService));

            BrowseCompareFolderCommand = new AsyncRelayCommand(BrowseForFolderAsync, _ => !IsComparing, HandleException);
            BrowseCompareFile1Command = new AsyncRelayCommand(BrowseForFile1Async, _ => !IsComparing, HandleException);
            BrowseCompareFile2Command = new AsyncRelayCommand(BrowseForFile2Async, _ => !IsComparing, HandleException);
            CompareDumpsCommand = new AsyncRelayCommand(CompareDumpsAsync, _ => !IsComparing && !string.IsNullOrWhiteSpace(CompareFolder), HandleException);
            CompareTwoFilesCommand = new AsyncRelayCommand(CompareTwoFilesAsync, _ => !IsComparing && !string.IsNullOrWhiteSpace(CompareFile1) && !string.IsNullOrWhiteSpace(CompareFile2), HandleException);
        }

        private async Task BrowseForFolderAsync()
        {
            var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare");
            if (result != null)
            {
                CompareFolder = result;
            }
        }

        private async Task BrowseForFile1Async()
        {
            var result = await _dialogService.OpenFilePickerAsync("Select File 1");
            if (result != null)
            {
                CompareFile1 = result;
            }
        }

        private async Task BrowseForFile2Async()
        {
            var result = await _dialogService.OpenFilePickerAsync("Select File 2");
            if (result != null)
            {
                CompareFile2 = result;
            }
        }

        private async Task CompareDumpsAsync()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            IsComparing = true;
            try
            {
                _logger.LogInformation("Starting folder comparison for {Folder}", CompareFolder);
                var progress = new Progress<string>(message => _logger.LogInformation(message));
                var report = await _fileComparisonService.CompareFolderAsync(CompareFolder, progress);

                // The ViewModel is now unaware of the specific View.
                // It asks the IViewService to show the result.
                await _viewService.ShowComparisonResultAsync(report);
                _logger.LogInformation("Folder comparison complete. Results shown.");
            }
            finally
            {
                IsComparing = false;
            }
        }

        private async Task CompareTwoFilesAsync()
        {
            if (!File.Exists(CompareFile1) || !File.Exists(CompareFile2))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select valid files.");
                return;
            }

            IsComparing = true;
            try
            {
                _logger.LogInformation("Requesting to show diff view for files: {File1} and {File2}", CompareFile1, CompareFile2);

                // The ViewModel no longer has a reference to any View.
                // It asks the IViewService to show the diff view.
                await _viewService.ShowDiffViewAsync(CompareFile1, CompareFile2);
            }
            finally
            {
                IsComparing = false;
            }
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in the File Compare view.");
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }
    }
}