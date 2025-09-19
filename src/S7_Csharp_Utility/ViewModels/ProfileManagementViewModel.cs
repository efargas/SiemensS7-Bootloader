using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;

namespace S7_Csharp_Utility.ViewModels
{
    public class ProfileManagementViewModel : ViewModelBase
    {
        private DeviceProfile _profile;
        public DeviceProfile Profile
        {
            get => _profile;
            set
            {
                _profile = value;
                OnPropertyChanged();
            }
        }

        public ICommand LoadProfileCommand { get; }
        public ICommand SaveProfileCommand { get; }
        public ICommand SaveAsNewProfileCommand { get; }
        public ICommand AddRegionCommand { get; }
        public ICommand RemoveRegionCommand { get; }

        private readonly ConfigurationService _configService;
        private readonly Interfaces.IDialogService _dialogService;
        private string? _currentProfilePath;

        public ProfileManagementViewModel(ConfigurationService configService, Interfaces.IDialogService dialogService)
        {
            _configService = configService;
            _dialogService = dialogService;
            _profile = new DeviceProfile();

            LoadProfileCommand = new RelayCommand(async _ => await LoadProfile());
            SaveProfileCommand = new RelayCommand(async _ => await SaveProfile(), _ => !string.IsNullOrEmpty(_currentProfilePath));
            SaveAsNewProfileCommand = new RelayCommand(async _ => await SaveAsNewProfile());
            AddRegionCommand = new RelayCommand(_ => AddRegion());
            RemoveRegionCommand = new RelayCommand(region => RemoveRegion(region), region => region != null);
        }

        private async Task LoadProfile()
        {
            var path = await _dialogService.ShowOpenFileDialogAsync("Load Profile", "json", "JSON Profiles");
            if (path != null)
            {
                var profile = await _configService.LoadProfileAsync(path);
                if (profile != null)
                {
                    Profile = profile;
                    _currentProfilePath = path;
                }
            }
        }

        private async Task SaveProfile()
        {
            if (_currentProfilePath != null)
            {
                await _configService.SaveProfileAsync(Profile, _currentProfilePath);
                await _dialogService.ShowMessageAsync("Profile Saved", "The profile has been saved successfully.");
            }
        }

        private async Task SaveAsNewProfile()
        {
            var path = await _dialogService.ShowSaveFileDialogAsync("Save New Profile", "json", "JSON Profiles");
            if (path != null)
            {
                await _configService.SaveProfileAsync(Profile, path);
                _currentProfilePath = path;
                await _dialogService.ShowMessageAsync("Profile Saved", "The new profile has been saved successfully.");
            }
        }

        private void AddRegion()
        {
            Profile.Regions.Add(new MemoryRegion());
        }

        private void RemoveRegion(object? region)
        {
            if (region is MemoryRegion memoryRegion)
            {
                Profile.Regions.Remove(memoryRegion);
            }
        }
    }
}
