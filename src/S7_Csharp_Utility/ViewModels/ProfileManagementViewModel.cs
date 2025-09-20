using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility.ViewModels
{
    public class ProfileManagementViewModel : ViewModelBase
    {
        private readonly ConfigurationService _configService;
        private readonly Interfaces.IDialogService _dialogService;
        private Action<DeviceProfile> _onSetActiveProfile;

        public ObservableCollection<DeviceProfile> Profiles { get; } = new ObservableCollection<DeviceProfile>();

        private DeviceProfile _selectedProfile;
        public DeviceProfile SelectedProfile
        {
            get => _selectedProfile;
            set
            {
                _selectedProfile = value;
                OnPropertyChanged();
                ((RelayCommand)SaveProfileCommand).RaiseCanExecuteChanged();
                ((RelayCommand)DeleteProfileCommand).RaiseCanExecuteChanged();
                ((RelayCommand)AddRegionCommand).RaiseCanExecuteChanged();
                ((RelayCommand)RemoveRegionCommand).RaiseCanExecuteChanged();
                ((RelayCommand)SetActiveProfileCommand).RaiseCanExecuteChanged();
            }
        }

        private MemoryRegion _selectedRegion;
        public MemoryRegion SelectedRegion
        {
            get => _selectedRegion;
            set
            {
                _selectedRegion = value;
                OnPropertyChanged();
                ((RelayCommand)RemoveRegionCommand).RaiseCanExecuteChanged();
            }
        }

        public ICommand AddProfileCommand { get; }
        public ICommand DeleteProfileCommand { get; }
        public ICommand SaveProfileCommand { get; }
        public ICommand AddRegionCommand { get; }
        public ICommand RemoveRegionCommand { get; }
        public ICommand SetActiveProfileCommand { get; }

        public ProfileManagementViewModel(ConfigurationService configService, Interfaces.IDialogService dialogService, Action<DeviceProfile> onSetActiveProfile)
        {
            _configService = configService;
            _dialogService = dialogService;
            _onSetActiveProfile = onSetActiveProfile;

            AddProfileCommand = new RelayCommand(_ => AddProfile());
            DeleteProfileCommand = new RelayCommand(async _ => await DeleteProfile(), _ => SelectedProfile != null);
            SaveProfileCommand = new RelayCommand(async _ => await SaveProfile(), _ => SelectedProfile != null);
            AddRegionCommand = new RelayCommand(_ => AddRegion(), _ => SelectedProfile != null);
            RemoveRegionCommand = new RelayCommand(_ => RemoveRegion(), _ => SelectedRegion != null);
            SetActiveProfileCommand = new RelayCommand(_ => SetActiveProfile(), _ => SelectedProfile != null);

            LoadProfilesAsync();
        }

        private async void LoadProfilesAsync()
        {
            var profiles = await _configService.LoadAllProfilesAsync();
            Profiles.Clear();
            foreach (var profile in profiles)
            {
                Profiles.Add(profile);
            }
        }

        private void AddProfile()
        {
            var newProfile = new DeviceProfile { ModelName = "New Profile" };
            Profiles.Add(newProfile);
            SelectedProfile = newProfile;
        }

        private async Task DeleteProfile()
        {
            if (SelectedProfile == null) return;

            if (!string.IsNullOrEmpty(SelectedProfile.FilePath))
            {
                await _configService.DeleteProfileAsync(SelectedProfile.FilePath);
            }
            Profiles.Remove(SelectedProfile);
            SelectedProfile = null;
        }

        private async Task SaveProfile()
        {
            if (SelectedProfile == null) return;

            if (string.IsNullOrEmpty(SelectedProfile.FilePath))
            {
                var profilesDir = _configService.GetProfilesDirectory();
                // Sanitize ModelName to create a valid file name
                var fileName = string.Join("_", SelectedProfile.ModelName.Split(Path.GetInvalidFileNameChars()));
                SelectedProfile.FilePath = Path.Combine(profilesDir, $"{fileName}.json");
            }

            await _configService.SaveProfileAsync(SelectedProfile, SelectedProfile.FilePath);
            await _dialogService.ShowMessageAsync("Profile Saved", "The profile has been saved successfully.");
        }

        private void AddRegion()
        {
            if (SelectedProfile == null) return;
            SelectedProfile.Regions.Add(new MemoryRegion { Name = "New Region" });
        }

        private void RemoveRegion()
        {
            if (SelectedProfile == null || SelectedRegion == null) return;
            SelectedProfile.Regions.Remove(SelectedRegion);
        }

        private void SetActiveProfile()
        {
            if (SelectedProfile == null) return;
            _onSetActiveProfile?.Invoke(SelectedProfile);
        }
    }
}
