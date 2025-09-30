using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Services;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The view model for managing device profiles.
    /// </summary>
    public class ProfileManagementViewModel : ViewModelBase
    {
        private readonly ConfigurationService _configService;
        private readonly IDialogService _dialogService;

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

        public ProfileManagementViewModel(ConfigurationService configService, IDialogService dialogService)
        {
            _configService = configService;
            _dialogService = dialogService;

            AddProfileCommand = new RelayCommand(AddProfile);
            DeleteProfileCommand = new AsyncRelayCommand(DeleteProfileAsync, () => SelectedProfile != null);
            SaveProfileCommand = new AsyncRelayCommand(SaveProfileAsync, () => SelectedProfile != null);
            AddRegionCommand = new RelayCommand(AddRegion, () => SelectedProfile != null);
            RemoveRegionCommand = new RelayCommand(RemoveRegion, () => SelectedRegion != null);

            // Fire and forget is acceptable here for initial load.
            _ = LoadProfilesAsync();
        }

        private async Task LoadProfilesAsync()
        {
            try
            {
                var profiles = await _configService.LoadAllProfilesAsync();
                Profiles.Clear();
                foreach (var profile in profiles)
                {
                    Profiles.Add(profile);
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error Loading Profiles", $"An error occurred while loading device profiles: {ex.Message}");
            }
        }

        private void AddProfile()
        {
            var newProfile = new DeviceProfile { ModelName = "New Profile" };
            Profiles.Add(newProfile);
            SelectedProfile = newProfile;
        }

        private async Task DeleteProfileAsync()
        {
            if (SelectedProfile == null) return;

            if (!string.IsNullOrEmpty(SelectedProfile.FilePath))
            {
                await _configService.DeleteProfileAsync(SelectedProfile.FilePath);
            }
            Profiles.Remove(SelectedProfile);
            SelectedProfile = null;
        }

        private async Task SaveProfileAsync()
        {
            if (SelectedProfile == null) return;

            if (string.IsNullOrEmpty(SelectedProfile.FilePath))
            {
                var profilesDir = _configService.GetProfilesDirectory();
                var fileName = string.Join("_", SelectedProfile.ModelName.Split(Path.GetInvalidFileNameChars()));
                SelectedProfile.FilePath = Path.Combine(profilesDir, $"{fileName}.json");
            }

            await _configService.SaveProfileAsync(SelectedProfile, SelectedProfile.FilePath);
            await _dialogService.ShowMessageAsync("Profile Saved", "The profile has been saved successfully.");
        }

        private void AddRegion()
        {
            if (SelectedProfile == null) return;
            SelectedProfile.Regions.Add(new MemoryRegion { Name = "New Region", Address = "0x0", Size = 16 });
        }

        private void RemoveRegion()
        {
            if (SelectedProfile == null || SelectedRegion == null) return;
            SelectedProfile.Regions.Remove(SelectedRegion);
        }
    }
}