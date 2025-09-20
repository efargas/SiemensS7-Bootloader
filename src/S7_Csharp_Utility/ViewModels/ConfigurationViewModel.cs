using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using System;

namespace S7_Csharp_Utility.ViewModels
{
    public class ConfigurationViewModel : ViewModelBase
    {
        private readonly Interfaces.IDialogService _dialogService;
        private readonly ConfigurationService _configService;
        private readonly MainWindowViewModel _mainViewModel;

        public string PayloadsPath
        {
            get => _mainViewModel.PayloadsPath;
            set => _mainViewModel.PayloadsPath = value;
        }

        public string DumpsPath
        {
            get => _mainViewModel.DumpsPath;
            set => _mainViewModel.DumpsPath = value;
        }

        public string LogsPath
        {
            get => _mainViewModel.LogsPath;
            set => _mainViewModel.LogsPath = value;
        }

        public string ExtractionPath
        {
            get => _mainViewModel.ExtractionPath;
            set => _mainViewModel.ExtractionPath = value;
        }

        public ICommand BrowsePayloadsFolderCommand { get; }
        public ICommand BrowseDumpsFolderCommand { get; }
        public ICommand BrowseLogsFolderCommand { get; }
        public ICommand BrowseExtractionFolderCommand { get; }
        public ICommand SavePathsCommand { get; }
        public ICommand LoadDefaultPathsCommand { get; }
        public ICommand SaveConfigurationCommand { get; }
        public ICommand LoadConfigurationCommand { get; }

        public ConfigurationViewModel(MainWindowViewModel mainViewModel, Interfaces.IDialogService dialogService, ConfigurationService configService)
        {
            _mainViewModel = mainViewModel;
            _dialogService = dialogService;
            _configService = configService;

            BrowsePayloadsFolderCommand = new RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if (result != null) PayloadsPath = result; }, _ => CanExecute());
            BrowseDumpsFolderCommand = new RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if (result != null) DumpsPath = result; }, _ => CanExecute());
            BrowseLogsFolderCommand = new RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if (result != null) LogsPath = result; }, _ => CanExecute());
            BrowseExtractionFolderCommand = new RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if (result != null) ExtractionPath = result; }, _ => CanExecute());

            SaveConfigurationCommand = new RelayCommand(_ => SaveConfiguration());
            LoadConfigurationCommand = new RelayCommand(_ => LoadConfiguration());
            SavePathsCommand = new RelayCommand(_ => SaveConfiguration(), _ => CanExecute());
            LoadDefaultPathsCommand = new RelayCommand(_ => LoadDefaultPaths(), _ => CanExecute());
        }

        private bool CanExecute()
        {
            return !_mainViewModel.IsUploadingStager && !_mainViewModel.IsDumpingMemory && !_mainViewModel.IsComparing;
        }

        private async void SaveConfiguration()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Files");
            if (path != null)
            {
                await _configService.SaveConfiguration(_mainViewModel, path);
            }
        }

        private async void LoadConfiguration()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Files");
            if (path != null)
            {
                await _configService.LoadConfiguration(_mainViewModel, path);
            }
        }

        private void LoadDefaultPaths()
        {
            PayloadsPath = ApplicationConfiguration.GetPayloadsPath();
            DumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();
            LogsPath = ApplicationConfiguration.GetDefaultLogsPath();
            ExtractionPath = ApplicationConfiguration.GetDefaultExtractionPath();
        }
    }
}
