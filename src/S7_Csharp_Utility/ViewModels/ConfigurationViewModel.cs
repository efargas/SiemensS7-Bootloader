#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using System;
using System.IO;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the configuration.
    /// </summary>
    public class ConfigurationViewModel : ViewModelBase
    {
        private readonly IApplicationStateService _state;
        private readonly IDialogService _dialogService;

        public string PayloadsPath { get => _state.PayloadsPath; set => _state.PayloadsPath = value; }
        public string DumpsPath { get => _state.DumpsPath; set => _state.DumpsPath = value; }
        public string LogsPath { get => _state.LogsPath; set => _state.LogsPath = value; }
        public string ExtractionPath { get => _state.ExtractionPath; set => _state.ExtractionPath = value; }

        public ICommand BrowsePayloadsFolderCommand { get; }
        public ICommand BrowseDumpsFolderCommand { get; }
        public ICommand BrowseLogsFolderCommand { get; }
        public ICommand BrowseExtractionFolderCommand { get; }
        public ICommand LoadDefaultPathsCommand { get; }
        public ICommand SavePathsCommand { get; }

        public ConfigurationViewModel(IApplicationStateService applicationStateService, IDialogService dialogService)
        {
            _state = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));

            _state.PropertyChanged += (s, e) => OnPropertyChanged(e.PropertyName);

            BrowsePayloadsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if (result != null) PayloadsPath = result; });
            BrowseDumpsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if (result != null) DumpsPath = result; });
            BrowseLogsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if (result != null) LogsPath = result; });
            BrowseExtractionFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if (result != null) ExtractionPath = result; });
            LoadDefaultPathsCommand = new RelayCommand(_ => LoadDefaultPaths());
            SavePathsCommand = new AsyncRelayCommand(async _ => await _state.SaveConfigurationAsync());
        }

        private void LoadDefaultPaths()
        {
            _state.PayloadsPath = ApplicationConfiguration.GetPayloadsPath();
            _state.DumpsPath = ApplicationConfiguration.GetDefaultDumpsPath();
            _state.LogsPath = ApplicationConfiguration.GetDefaultLogsPath();
            _state.ExtractionPath = ApplicationConfiguration.GetDefaultExtractionPath();
        }
    }
}
