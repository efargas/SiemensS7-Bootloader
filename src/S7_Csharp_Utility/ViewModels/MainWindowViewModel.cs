#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application. Acts as the central orchestrator for child viewmodels and application-level commands.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private readonly ILogger<MainWindowViewModel> _logger;
        private readonly IDialogService _dialogService;
        private readonly IViewService _viewService;
        private readonly IApplicationStateService _appStateService;

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
            IApplicationStateService appStateService,
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
            _appStateService = appStateService;

            // Child ViewModels
            PlcConnectionViewModel = plcConnectionViewModel;
            ModbusPowerSupplyViewModel = modbusPowerSupplyViewModel;
            ConfigurationViewModel = configurationViewModel;
            FileCompareViewModel = fileCompareViewModel;
            LogViewModel = logViewModel;
            SocatLogViewModel = socatLogViewModel;

            // Commands
            LoadProfileCommand = new AsyncRelayCommand(LoadProfileAsync, () => true, HandleException);
            SaveConfigurationCommand = new AsyncRelayCommand(SaveConfigurationOnExitAsync, () => true, HandleException);
            ShowProfileManagementCommand = new AsyncRelayCommand(ShowProfileManagementAsync, () => true, HandleException);
            ShowFirmwareUnpackerCommand = new RelayCommand(() => _viewService.ShowFirmwareUnpackerWindow(ConfigurationViewModel.ExtractionPath));
            ShowHexViewerCommand = new RelayCommand(() => _viewService.ShowHexViewerWindow());
            ExitCommand = new RelayCommand(() => _viewService.Exit());
        }

        public async Task LoadConfigurationOnStartupAsync()
        {
            var config = await _appStateService.LoadStateFromDefaultLocationAsync();
            if (config != null)
            {
                ApplyConfiguration(config);
            }
            else
            {
                // If no config exists, save the current default state to create one.
                await SaveConfigurationOnExitAsync();
            }
        }

        public Task SaveConfigurationOnExitAsync()
        {
            var config = new ApplicationConfiguration();
            // Gather state from all viewmodels into the config object
            ConfigurationViewModel.SaveToAppConfig(config);
            PlcConnectionViewModel.SaveToAppConfig(config);
            ModbusPowerSupplyViewModel.SaveToAppConfig(config);
            config.CompareFolder = FileCompareViewModel.CompareFolder;
            config.CompareFile1 = FileCompareViewModel.CompareFile1;
            config.CompareFile2 = FileCompareViewModel.CompareFile2;

            return _appStateService.SaveStateToDefaultLocationAsync(config);
        }

        private async Task LoadProfileAsync()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles");
            if (path != null)
            {
                var profile = await _appStateService.LoadProfileAsync(path);
                if (profile != null)
                {
                    ApplyProfile(profile);
                }
            }
        }

        private async Task ShowProfileManagementAsync()
        {
            var selectedProfile = await _viewService.ShowProfileManagementWindowAsync();
            if (selectedProfile != null)
            {
                ApplyProfile(selectedProfile);
            }
        }

        private void ApplyProfile(DeviceProfile profile)
        {
            LoadedProfile = profile;
            ConfigurationViewModel.ApplyProfile(profile);
            _logger.LogInformation("Applied device profile: {ProfileName}", profile.ModelName);
        }

        private void ApplyConfiguration(ApplicationConfiguration config)
        {
            ConfigurationViewModel.LoadFromAppConfig(config);
            PlcConnectionViewModel.LoadFromAppConfig(config);
            ModbusPowerSupplyViewModel.LoadFromAppConfig(config);
            FileCompareViewModel.CompareFolder = config.CompareFolder ?? string.Empty;
            FileCompareViewModel.CompareFile1 = config.CompareFile1 ?? string.Empty;
            FileCompareViewModel.CompareFile2 = config.CompareFile2 ?? string.Empty;
            _logger.LogInformation("Application configuration loaded.");
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in the main window.");
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }
    }
}