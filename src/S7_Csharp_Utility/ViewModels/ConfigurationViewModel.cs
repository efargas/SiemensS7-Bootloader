#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using System;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the configuration.
    /// </summary>
    public class ConfigurationViewModel : ViewModelBase
    {
        private readonly IDialogService _dialogService;
        private readonly ConfigurationService _configService;

        private string _payloadsPath = ApplicationConfiguration.GetPayloadsPath();
        /// <summary>
        /// Gets or sets the path to the payloads.
        /// </summary>
        public string PayloadsPath
        {
            get => _payloadsPath;
            set => SetProperty(ref _payloadsPath, value);
        }

        private string _dumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();
        /// <summary>
        /// Gets or sets the path to the dumps.
        /// </summary>
        public string DumpsPath
        {
            get => _dumpsPath;
            set => SetProperty(ref _dumpsPath, value);
        }

        private string _logsPath = ApplicationConfiguration.GetDefaultLogsPath();
        /// <summary>
        /// Gets or sets the path to the logs.
        /// </summary>
        public string LogsPath
        {
            get => _logsPath;
            set => SetProperty(ref _logsPath, value);
        }

        private string _extractionPath = ApplicationConfiguration.GetDefaultExtractionPath();
        /// <summary>
        /// Gets or sets the path to the extraction folder.
        /// </summary>
        public string ExtractionPath
        {
            get => _extractionPath;
            set => SetProperty(ref _extractionPath, value);
        }

        /// <summary>
        /// Gets the command to browse for the payloads folder.
        /// </summary>
        public ICommand BrowsePayloadsFolderCommand { get; }
        /// <summary>
        /// Gets the command to browse for the dumps folder.
        /// </summary>
        public ICommand BrowseDumpsFolderCommand { get; }
        /// <summary>
        /// Gets the command to browse for the logs folder.
        /// </summary>
        public ICommand BrowseLogsFolderCommand { get; }
        /// <summary>
        /// Gets the command to browse for the extraction folder.
        /// </summary>
        public ICommand BrowseExtractionFolderCommand { get; }
        /// <summary>
        /// Gets the command to load the default paths.
        /// </summary>
        public ICommand LoadDefaultPathsCommand { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationViewModel"/> class.
        /// </summary>
        public ConfigurationViewModel(IDialogService dialogService, ConfigurationService configService)
        {
            _dialogService = dialogService;
            _configService = configService;

            BrowsePayloadsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if (result != null) PayloadsPath = result; });
            BrowseDumpsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if (result != null) DumpsPath = result; });
            BrowseLogsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if (result != null) LogsPath = result; });
            BrowseExtractionFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if (result != null) ExtractionPath = result; });
            LoadDefaultPathsCommand = new RelayCommand(_ => LoadDefaultPaths());
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
