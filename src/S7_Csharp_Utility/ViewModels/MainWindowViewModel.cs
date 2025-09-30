#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using System;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application. Acts as the central orchestrator.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private const string ConfigFileName = "config.json";

        private readonly ILogger<MainWindowViewModel> _logger;
        private readonly IDialogService _dialogService;
        private readonly IViewService _viewService;
        private readonly ConfigurationService _configService;

        public PlcConnectionViewModel PlcConnectionViewModel { get; }
        public ModbusPowerSupplyViewModel ModbusPowerSupplyViewModel { get; }
        public ConfigurationViewModel ConfigurationViewModel { get; }
        public FileCompareViewModel FileCompareViewModel { get; }
        public LogViewModel LogViewModel { get; }
        public SocatLogViewModel SocatLogViewModel { get; }

        private DeviceProfile? _loadedProfile;
        public DeviceProfile? LoadedProfile
        {
            get => _loadedProfile;
            set => SetProperty(ref _loadedProfile, value);
        }

        public ICommand LoadProfileCommand { get; }
        public ICommand SaveConfigurationCommand { get; }
        public ICommand ShowProfileManagementCommand { get; }
        public ICommand ShowFirmwareUnpackerCommand { get; }
        public ICommand ShowHexViewerCommand { get; }
        public ICommand ExitCommand { get; }

        public MainWindowViewModel(
            ILogger<MainWindowViewModel> logger,
            IDialogService dialogService,
            IViewService viewService,
            ConfigurationService configService,
            PlcConnectionViewModel plcConnectionViewModel,
            ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
            ConfigurationViewModel configurationViewModel,
            FileCompareViewModel fileCompareViewModel,
            LogViewModel logViewModel,
            SocatLogViewModel socatLogViewModel)
        {
            _logger = logger;
            _dialogService = dialogService;
            _viewService = viewService;
            _configService = configService;

            // Child ViewModels
            PlcConnectionViewModel = plcConnectionViewModel;
            ModbusPowerSupplyViewModel = modbusPowerSupplyViewModel;
            ConfigurationViewModel = configurationViewModel;
            FileCompareViewModel = fileCompareViewModel;
            LogViewModel = logViewModel;
            SocatLogViewModel = socatLogViewModel;

            // Commands
            LoadProfileCommand = new AsyncRelayCommand(LoadProfileAsync, _ => true, HandleException);
            SaveConfigurationCommand = new AsyncRelayCommand(SaveConfigurationOnExitAsync, _ => true, HandleException);
            ShowProfileManagementCommand = new RelayCommand(ShowProfileManagement);
            ShowFirmwareUnpackerCommand = new RelayCommand(ShowFirmwareUnpacker);
            ShowHexViewerCommand = new RelayCommand(ShowHexViewer);
            ExitCommand = new RelayCommand(() => _viewService.Exit());
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in the main window.");
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private void ShowProfileManagement()
        {
            _viewService.ShowProfileManagementWindow(_configService, profile =>
            {
                if (profile != null)
                {
                    LoadedProfile = profile;
                    // Apply profile settings to relevant viewmodels
                    ConfigurationViewModel.ApplyProfile(profile);
                }
            });
        }

        private void ShowFirmwareUnpacker()
        {
            _viewService.ShowFirmwareUnpackerWindow(ConfigurationViewModel.ExtractionPath);
        }

        private void ShowHexViewer() => _viewService.ShowHexViewerWindow();

        private async Task LoadProfileAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles");
            if (path != null)
            {
                var profile = await _configService.LoadProfileAsync(path);
                if (profile != null)
                {
                    LoadedProfile = profile;
                    ConfigurationViewModel.ApplyProfile(profile);
                }
            }
        }

        public async Task LoadConfigurationOnStartup()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = await _configService.LoadConfigurationAsync(path);
                if (config != null)
                {
                    ConfigurationViewModel.LoadFromAppConfig(config);
                    PlcConnectionViewModel.LoadFromAppConfig(config);
                    ModbusPowerSupplyViewModel.LoadFromAppConfig(config);
                    FileCompareViewModel.CompareFolder = config.CompareFolder ?? string.Empty;
                    FileCompareViewModel.CompareFile1 = config.CompareFile1 ?? string.Empty;
                    FileCompareViewModel.CompareFile2 = config.CompareFile2 ?? string.Empty;
                }
                else
                {
                    await SaveConfigurationOnExitAsync();
                    _logger.LogInformation("No configuration found. Created default configuration at {Path}", path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not load or create configuration.");
            }
        }

        public async Task SaveConfigurationOnExitAsync()
        {
            try
            {
                var path = System.IO.Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                var config = new ApplicationConfiguration();

                // Populate config from all viewmodels
                ConfigurationViewModel.SaveToAppConfig(config);
                PlcConnectionViewModel.SaveToAppConfig(config);
                ModbusPowerSupplyViewModel.SaveToAppConfig(config);
                config.CompareFolder = FileCompareViewModel.CompareFolder;
                config.CompareFile1 = FileCompareViewModel.CompareFile1;
                config.CompareFile2 = FileCompareViewModel.CompareFile2;

                await _configService.SaveConfigurationAsync(config, path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not save configuration.");
            }
        }
    }
}