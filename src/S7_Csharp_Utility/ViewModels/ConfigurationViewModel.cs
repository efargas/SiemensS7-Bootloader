#nullable enable
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using System;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for the configuration.
    /// </summary>
    public class ConfigurationViewModel : ViewModelBase
    {
        private readonly Interfaces.IDialogService _dialogService;
        private readonly ConfigurationService _configService;
        private readonly MainWindowViewModel _mainViewModel;

        /// <summary>
        /// Gets or sets the path to the payloads.
        /// </summary>
        public string PayloadsPath
        {
            get => _mainViewModel.PayloadsPath;
            set => _mainViewModel.PayloadsPath = value;
        }

        /// <summary>
        /// Gets or sets the path to the dumps.
        /// </summary>
        public string DumpsPath
        {
            get => _mainViewModel.DumpsPath;
            set => _mainViewModel.DumpsPath = value;
        }

        /// <summary>
        /// Gets or sets the path to the logs.
        /// </summary>
        public string LogsPath
        {
            get => _mainViewModel.LogsPath;
            set => _mainViewModel.LogsPath = value;
        }

        /// <summary>
        /// Gets or sets the path to the extraction folder.
        /// </summary>
        public string ExtractionPath
        {
            get => _mainViewModel.ExtractionPath;
            set => _mainViewModel.ExtractionPath = value;
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
        /// Gets the command to save the paths.
        /// </summary>
        public ICommand SavePathsCommand { get; }
        /// <summary>
        /// Gets the command to load the default paths.
        /// </summary>
        public ICommand LoadDefaultPathsCommand { get; }
        /// <summary>
        /// Gets the command to save the configuration.
        /// </summary>
        public ICommand SaveConfigurationCommand { get; }
        /// <summary>
        /// Gets the command to load the configuration.
        /// </summary>
        public ICommand LoadConfigurationCommand { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationViewModel"/> class.
        /// </summary>
        public ConfigurationViewModel(MainWindowViewModel mainViewModel, Interfaces.IDialogService dialogService, ConfigurationService configService)
        {
            _mainViewModel = mainViewModel;
            _dialogService = dialogService;
            _configService = configService;

            BrowsePayloadsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Payloads Folder"); if (result != null) PayloadsPath = result; }, _ => CanExecute(), HandleException);
            BrowseDumpsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Dumps Folder"); if (result != null) DumpsPath = result; }, _ => CanExecute(), HandleException);
            BrowseLogsFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Logs Folder"); if (result != null) LogsPath = result; }, _ => CanExecute(), HandleException);
            BrowseExtractionFolderCommand = new AsyncRelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Extraction Folder"); if (result != null) ExtractionPath = result; }, _ => CanExecute(), HandleException);

            SaveConfigurationCommand = new AsyncRelayCommand(_ => SaveConfigurationAsync(), null, HandleException);
            LoadConfigurationCommand = new AsyncRelayCommand(_ => LoadConfigurationAsync(), null, HandleException);
            SavePathsCommand = new AsyncRelayCommand(_ => SaveConfigurationAsync(), _ => CanExecute(), HandleException);
            LoadDefaultPathsCommand = new RelayCommand(_ => LoadDefaultPaths(), _ => CanExecute());
        }

        private bool CanExecute()
        {
            return !_mainViewModel.IsUploadingStager && !_mainViewModel.IsDumpingMemory && !_mainViewModel.IsComparing;
        }

        private void HandleException(System.Exception ex)
        {
            _mainViewModel.Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private async Task SaveConfigurationAsync()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save Configuration", "json", "JSON Files").ConfigureAwait(false);
            if (path != null)
            {
                if (_mainViewModel.PlcConnectionViewModel == null || _mainViewModel.ModbusPowerSupplyViewModel == null || _mainViewModel.FileCompareViewModel == null)
                {
                    return;
                }
                var config = new ApplicationConfiguration
                {
                    PlcHost = _mainViewModel.PlcConnectionViewModel.PlcHost,
                    PlcPort = _mainViewModel.PlcConnectionViewModel.PlcPort,
                    ModbusHost = _mainViewModel.ModbusPowerSupplyViewModel.ModbusHost,
                    ModbusPort = _mainViewModel.ModbusPowerSupplyViewModel.ModbusPort,
                    ModbusCoil = _mainViewModel.ModbusPowerSupplyViewModel.ModbusCoil,
                    DelaySeconds = _mainViewModel.ModbusPowerSupplyViewModel.DelaySeconds,
                    DumpAddress = _mainViewModel.DumpAddress,
                    DumpLength = _mainViewModel.DumpLength,
                    CompareFolder = _mainViewModel.FileCompareViewModel.CompareFolder,
                    CompareFile1 = _mainViewModel.FileCompareViewModel.CompareFile1,
                    CompareFile2 = _mainViewModel.FileCompareViewModel.CompareFile2,
                    SelectedSerialPort = _mainViewModel.PlcConnectionViewModel.SelectedSerialPort,
                    SocatTcpPort = _mainViewModel.PlcConnectionViewModel.SocatTcpPort,
                    SelectedBaudRate = _mainViewModel.PlcConnectionViewModel.SelectedBaudRate,
                    SelectedParity = _mainViewModel.PlcConnectionViewModel.SelectedParity,
                    SelectedStopBits = _mainViewModel.PlcConnectionViewModel.SelectedStopBits,
                    SelectedFlowControl = _mainViewModel.PlcConnectionViewModel.SelectedFlowControl,
                    SocatVerbose = _mainViewModel.PlcConnectionViewModel.SocatVerbose,
                    SocatHexDump = _mainViewModel.PlcConnectionViewModel.SocatHexDump,
                    SocatBlockSize = _mainViewModel.PlcConnectionViewModel.SocatBlockSize,
                    PayloadsPath = PayloadsPath,
                    DumpsPath = DumpsPath,
                    LogsPath = LogsPath,
                    ExtractionPath = ExtractionPath
                };
                await _configService.SaveConfigurationAsync(config, path).ConfigureAwait(false);
            }
        }

        private async Task LoadConfigurationAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Configuration", "json", "JSON Files").ConfigureAwait(false);
            if (path != null)
            {
                if (_mainViewModel.PlcConnectionViewModel == null || _mainViewModel.ModbusPowerSupplyViewModel == null || _mainViewModel.FileCompareViewModel == null)
                {
                    return;
                }
                var config = await _configService.LoadConfigurationAsync(path).ConfigureAwait(false);
                if (config != null)
                {
                    _mainViewModel.PlcConnectionViewModel.PlcHost = config.PlcHost;
                    _mainViewModel.PlcConnectionViewModel.PlcPort = config.PlcPort;
                    _mainViewModel.ModbusPowerSupplyViewModel.ModbusHost = config.ModbusHost;
                    _mainViewModel.ModbusPowerSupplyViewModel.ModbusPort = config.ModbusPort;
                    _mainViewModel.ModbusPowerSupplyViewModel.ModbusCoil = config.ModbusCoil;
                    _mainViewModel.ModbusPowerSupplyViewModel.DelaySeconds = config.DelaySeconds;
                    _mainViewModel.DumpAddress = config.DumpAddress;
                    _mainViewModel.DumpLength = config.DumpLength;
                    _mainViewModel.FileCompareViewModel.CompareFolder = config.CompareFolder;
                    _mainViewModel.FileCompareViewModel.CompareFile1 = config.CompareFile1;
                    _mainViewModel.FileCompareViewModel.CompareFile2 = config.CompareFile2;
                    _mainViewModel.PlcConnectionViewModel.SelectedSerialPort = config.SelectedSerialPort;
                    _mainViewModel.PlcConnectionViewModel.SocatTcpPort = config.SocatTcpPort;
                    _mainViewModel.PlcConnectionViewModel.SelectedBaudRate = config.SelectedBaudRate;
                    _mainViewModel.PlcConnectionViewModel.SelectedParity = config.SelectedParity;
                    _mainViewModel.PlcConnectionViewModel.SelectedStopBits = config.SelectedStopBits;
                    _mainViewModel.PlcConnectionViewModel.SelectedFlowControl = config.SelectedFlowControl;
                    _mainViewModel.PlcConnectionViewModel.SocatVerbose = config.SocatVerbose;
                    _mainViewModel.PlcConnectionViewModel.SocatHexDump = config.SocatHexDump;
                    _mainViewModel.PlcConnectionViewModel.SocatBlockSize = config.SocatBlockSize;
                    PayloadsPath = config.PayloadsPath;
                    DumpsPath = config.DumpsPath;
                    LogsPath = config.LogsPath;
                    ExtractionPath = config.ExtractionPath;
                }
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
