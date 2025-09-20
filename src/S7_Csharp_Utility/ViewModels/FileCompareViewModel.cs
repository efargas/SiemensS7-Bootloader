using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    public class FileCompareViewModel : ViewModelBase
    {
        private readonly MainWindowViewModel _mainViewModel;
        private readonly Interfaces.IDialogService _dialogService;
        private readonly LoggingService _loggingService;

        private string _compareFolder = string.Empty;
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

        public ICommand BrowseCompareFolderCommand { get; }
        public ICommand BrowseCompareFile1Command { get; }
        public ICommand BrowseCompareFile2Command { get; }
        public ICommand CompareDumpsCommand { get; }
        public ICommand CompareTwoFilesCommand { get; }

        public FileCompareViewModel(MainWindowViewModel mainViewModel, Interfaces.IDialogService dialogService, LoggingService loggingService)
        {
            _mainViewModel = mainViewModel;
            _dialogService = dialogService;
            _loggingService = loggingService;

            BrowseCompareFolderCommand = new RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare"); if (result != null) CompareFolder = result; }, _ => CanExecute());
            BrowseCompareFile1Command = new RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 1"); if (result != null) CompareFile1 = result; }, _ => CanExecute());
            BrowseCompareFile2Command = new RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 2"); if (result != null) CompareFile2 = result; }, _ => CanExecute());
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
            return !_mainViewModel.IsUploadingStager && !_mainViewModel.IsDumpingMemory && !_mainViewModel.IsComparing;
        }

        private async Task CompareDumpsAsync()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !System.IO.Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            _mainViewModel.IsComparing = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer(message => _loggingService.Log(message, LogCategory.Info));
                var fileHashes = await comparer.ComputeFileHashesAsync(CompareFolder);
                var report = comparer.GenerateFolderCompareReport(fileHashes, CompareFolder);

                await _dialogService.ShowMessageAsync("Comparison Result", report);
                _loggingService.Log("Comparison complete. See popup for detailed result.");
            }
            catch (System.Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during folder compare: {ex.Message}");
                _loggingService.Log($"Error during folder compare: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                _mainViewModel.IsComparing = false;
            }
        }

        private async Task CompareTwoFilesAsync()
        {
            if (!System.IO.File.Exists(CompareFile1) || !System.IO.File.Exists(CompareFile2))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid file.");
                return;
            }

            _mainViewModel.IsComparing = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer();
                string hashA = await comparer.ComputeFileHashAsync(CompareFile1);
                string hashB = await comparer.ComputeFileHashAsync(CompareFile2);
                bool match = hashA == hashB;
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"File 1: {System.IO.Path.GetFileName(CompareFile1)}");
                sb.AppendLine($"MD5: {hashA}");
                sb.AppendLine($"File 2: {System.IO.Path.GetFileName(CompareFile2)}");
                sb.AppendLine($"MD5: {hashB}");
                sb.AppendLine(match ? "=> MATCH" : "=> DIFFER");

                await _dialogService.ShowMessageAsync("Comparison Result", sb.ToString());
                _loggingService.Log("Comparison complete. See popup for detailed result.");
            }
            catch (System.Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during file compare: {ex.Message}");
                _loggingService.Log($"Error during file compare: {ex.ToString()}", LogCategory.Error);
            }
            finally
            {
                _mainViewModel.IsComparing = false;
            }
        }
    }
}
