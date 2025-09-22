#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the file comparison.
    /// </summary>
    public class FileCompareViewModel : ViewModelBase
    {
        private readonly Interfaces.IDialogService _dialogService;
        private readonly LoggingService _loggingService;
        private readonly Interfaces.IViewService _viewService;
        
        private bool _isComparing;
        public bool IsComparing
        {
            get => _isComparing;
            set => SetProperty(ref _isComparing, value);
        }

        private string _compareFolder = string.Empty;
        /// <summary>
        /// Gets or sets the folder to compare.
        /// </summary>
        public string CompareFolder
        {
            get => _compareFolder;
            set
            {
                _compareFolder = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)CompareDumpsCommand).RaiseCanExecuteChanged();
            }
        }

        private string _compareFile1 = string.Empty;
        /// <summary>
        /// Gets or sets the first file to compare.
        /// </summary>
        public string CompareFile1
        {
            get => _compareFile1;
            set
            {
                _compareFile1 = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)CompareTwoFilesCommand).RaiseCanExecuteChanged();
            }
        }

        private string _compareFile2 = string.Empty;
        /// <summary>
        /// Gets or sets the second file to compare.
        /// </summary>
        public string CompareFile2
        {
            get => _compareFile2;
            set
            {
                _compareFile2 = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)CompareTwoFilesCommand).RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Gets the command to browse for the folder to compare.
        /// </summary>
        public ICommand BrowseCompareFolderCommand { get; }
        /// <summary>
        /// Gets the command to browse for the first file to compare.
        /// </summary>
        public ICommand BrowseCompareFile1Command { get; }
        /// <summary>
        /// Gets the command to browse for the second file to compare.
        /// </summary>
        public ICommand BrowseCompareFile2Command { get; }
        /// <summary>
        /// Gets the command to compare the dumps.
        /// </summary>
        public ICommand CompareDumpsCommand { get; }
        /// <summary>
        /// Gets the command to compare two files.
        /// </summary>
        public ICommand CompareTwoFilesCommand { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileCompareViewModel"/> class.
        /// </summary>
        public FileCompareViewModel(Interfaces.IDialogService dialogService, LoggingService loggingService, Interfaces.IViewService viewService)
        {
            _dialogService = dialogService;
            _loggingService = loggingService;
            _viewService = viewService;

            BrowseCompareFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare"); if (result != null) CompareFolder = result; }, _ => CanExecute(), HandleException);
            BrowseCompareFile1Command = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 1"); if (result != null) CompareFile1 = result; }, _ => CanExecute(), HandleException);
            BrowseCompareFile2Command = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 2"); if (result != null) CompareFile2 = result; }, _ => CanExecute(), HandleException);
            CompareDumpsCommand = new AsyncRelayCommand(_ => CompareDumpsAsync(), _ => CanExecute() && !string.IsNullOrWhiteSpace(CompareFolder), HandleException);
            CompareTwoFilesCommand = new AsyncRelayCommand(_ => CompareTwoFilesAsync(), _ => CanExecute() && !string.IsNullOrWhiteSpace(CompareFile1) && !string.IsNullOrWhiteSpace(CompareFile2), HandleException);
        }

        private void HandleException(System.Exception ex)
        {
            _loggingService.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private bool CanExecute()
        {
            return !IsComparing;
        }

        private async Task CompareDumpsAsync()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !System.IO.Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            IsComparing = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer(message => _loggingService.Log(message, LogCategory.Info));
                var fileHashes = await comparer.ComputeFileHashesAsync(CompareFolder);
                var report = comparer.GenerateFolderCompareReport(fileHashes, CompareFolder);

                var resultWindow = new Views.ComparisonResultWindow(report);
                await resultWindow.ShowDialog(_viewService.GetMainWindow());
                _loggingService.Log("Comparison complete. Results shown in dialog.");
            }
            catch (System.Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during folder compare: {ex.Message}");
                _loggingService.Log($"Error during folder compare: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                IsComparing = false;
            }
        }

        private async Task CompareTwoFilesAsync()
        {
            if (!System.IO.File.Exists(CompareFile1) || !System.IO.File.Exists(CompareFile2))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select valid files.");
                return;
            }

            IsComparing = true;
            try
            {
                _loggingService.Log($"Starting optimized comparison of files:", LogCategory.Info);
                _loggingService.Log($"  File 1: {CompareFile1}", LogCategory.Info);
                _loggingService.Log($"  File 2: {CompareFile2}", LogCategory.Info);

                var diffViewModel = new DiffViewModel(CompareFile1, CompareFile2);
                var diffView = new Views.DiffView
                {
                    DataContext = diffViewModel
                };
                await diffView.ShowDialog(_viewService.GetMainWindow());
                
                // Clean up the ViewModel when dialog closes
                diffViewModel.Dispose();
            }
            catch (System.Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during file compare: {ex.Message}");
                _loggingService.Log($"Error during file compare: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                IsComparing = false;
            }
        }
    }
}
