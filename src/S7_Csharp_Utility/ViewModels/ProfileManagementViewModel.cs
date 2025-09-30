using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for managing device profiles.
    /// </summary>
    public class ProfileManagementViewModel : ViewModelBase
    {
        private readonly IProfileManagerService _profileManager;
        private readonly IDialogService _dialogService;
        private readonly ILogger<ProfileManagementViewModel> _logger;

        public ObservableCollection<DeviceProfile> Profiles { get; } = new ObservableCollection<DeviceProfile>();

        private DeviceProfile? _selectedProfile;
        public DeviceProfile? SelectedProfile
        {
            get => _selectedProfile;
            set
            {
                if (SetProperty(ref _selectedProfile, value))
                {
                    (SaveProfileCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                    (DeleteProfileCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                    (AddRegionCommand as RelayCommand)?.RaiseCanExecuteChanged();
                    (RemoveRegionCommand as RelayCommand)?.RaiseCanExecuteChanged();
                }
            }
        }

        private MemoryRegion? _selectedRegion;
        public MemoryRegion? SelectedRegion
        {
            get => _selectedRegion;
            set
            {
                if (SetProperty(ref _selectedRegion, value))
                {
                    (RemoveRegionCommand as RelayCommand)?.RaiseCanExecuteChanged();
                }
            }
        }

        public ICommand AddProfileCommand { get; }
        public ICommand DeleteProfileCommand { get; }
        public ICommand SaveProfileCommand { get; }
        public ICommand AddRegionCommand { get; }
        public ICommand RemoveRegionCommand { get; }

        public ProfileManagementViewModel(
            IProfileManagerService profileManager,
            IDialogService dialogService,
            ILogger<ProfileManagementViewModel> logger)
        {
            _profileManager = profileManager;
            _dialogService = dialogService;
            _logger = logger;

            AddProfileCommand = new RelayCommand(AddProfile);
            DeleteProfileCommand = new AsyncRelayCommand(DeleteProfileAsync, () => SelectedProfile != null, HandleException);
            SaveProfileCommand = new AsyncRelayCommand(SaveProfileAsync, () => SelectedProfile != null, HandleException);
            AddRegionCommand = new RelayCommand(AddRegion, () => SelectedProfile != null);
            RemoveRegionCommand = new RelayCommand(RemoveRegion, () => SelectedRegion != null);

            _ = LoadProfilesAsync();
        }

        private async Task LoadProfilesAsync()
        {
            try
            {
                var profiles = await _profileManager.GetAllProfilesAsync();
                Profiles.Clear();
                foreach (var profile in profiles)
                {
                    Profiles.Add(profile);
                }
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
        }

        private void AddProfile()
        {
            var newProfile = _profileManager.CreateNewProfile();
            Profiles.Add(newProfile);
            SelectedProfile = newProfile;
        }

        private async Task DeleteProfileAsync()
        {
            if (SelectedProfile == null) return;

            await _profileManager.DeleteProfileAsync(SelectedProfile);
            Profiles.Remove(SelectedProfile);
            SelectedProfile = null;
            _logger.LogInformation("Profile deleted.");
        }

        private async Task SaveProfileAsync()
        {
            if (SelectedProfile == null) return;

            await _profileManager.SaveProfileAsync(SelectedProfile);
            await _dialogService.ShowMessageAsync("Profile Saved", "The profile has been saved successfully.");
            _logger.LogInformation("Profile '{ProfileName}' saved to {FilePath}", SelectedProfile.ModelName, SelectedProfile.FilePath);
        }

        private void AddRegion()
        {
            if (SelectedProfile == null) return;
            // The creation of a new region is simple view-state manipulation, so it can remain here.
            SelectedProfile.Regions.Add(new MemoryRegion { Name = "New Region", Address = "0x0", Size = 16 });
        }

        private void RemoveRegion()
        {
            if (SelectedProfile == null || SelectedRegion == null) return;
            SelectedProfile.Regions.Remove(SelectedRegion);
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An error occurred in the Profile Management view.");
            _dialogService.ShowMessageAsync("Error", $"An unexpected error occurred: {ex.Message}");
        }
    }
}