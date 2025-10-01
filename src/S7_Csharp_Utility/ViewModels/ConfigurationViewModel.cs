#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the configuration, responsible for managing user-configurable paths.
    /// </summary>
    public class ConfigurationViewModel : ViewModelBase
    {
        private readonly IDialogService _dialogService;
        private readonly IConfigurationService _configService;

        private string _payloadsPath = string.Empty;
        public string PayloadsPath
        {
            get => _payloadsPath;
            set => SetProperty(ref _payloadsPath, value);
        }

        private string _dumpsPath = string.Empty;
        public string DumpsPath
        {
            get => _dumpsPath;
            set => SetProperty(ref _dumpsPath, value);
        }

        private string _logsPath = string.Empty;
        public string LogsPath
        {
            get => _logsPath;
            set => SetProperty(ref _logsPath, value);
        }

        private string _extractionPath = string.Empty;
        public string ExtractionPath
        {
            get => _extractionPath;
            set => SetProperty(ref _extractionPath, value);
        }

        public ICommand BrowsePayloadsFolderCommand { get; }
        public ICommand BrowseDumpsFolderCommand { get; }
        public ICommand BrowseLogsFolderCommand { get; }
        public ICommand BrowseExtractionFolderCommand { get; }
        public ICommand LoadDefaultPathsCommand { get; }

        public ConfigurationViewModel(IDialogService dialogService, IConfigurationService configService)
        {
            _dialogService = dialogService;
            _configService = configService;

            BrowsePayloadsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if (result != null) PayloadsPath = result; });
            BrowseDumpsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if (result != null) DumpsPath = result; });
            BrowseLogsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if (result != null) LogsPath = result; });
            BrowseExtractionFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if (result != null) ExtractionPath = result; });
            LoadDefaultPathsCommand = new RelayCommand(LoadDefaultPaths);

            // Initialize with default paths
            LoadDefaultPaths();
        }

        private void LoadDefaultPaths()
        {
            PayloadsPath = _configService.GetPayloadsPath();
            DumpsPath = _configService.GetDefaultDumpsPath();
            LogsPath = _configService.GetDefaultLogsPath();
            ExtractionPath = _configService.GetDefaultExtractionPath();
        }

        public void ApplyProfile(DeviceProfile profile)
        {
            // This can be expanded later if profiles contain path configurations
        }

        public void LoadFromAppConfig(ApplicationConfiguration config)
        {
            PayloadsPath = config.PayloadsPath;
            DumpsPath = config.DumpsPath;
            LogsPath = config.LogsPath;
            ExtractionPath = config.ExtractionPath;
        }

        public void SaveToAppConfig(ApplicationConfiguration config)
        {
            config.PayloadsPath = PayloadsPath;
            config.DumpsPath = DumpsPath;
            config.LogsPath = LogsPath;
            config.ExtractionPath = ExtractionPath;
        }
    }
}