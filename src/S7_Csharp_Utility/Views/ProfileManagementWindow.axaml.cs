using Avalonia.Controls;
using Avalonia.Platform.Storage;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;
using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility
{
    public partial class ProfileManagementWindow : Window, IDialogService
    {
        public ProfileManagementWindow() : this(new ConfigurationService(), _ => { }) { }

        public ProfileManagementWindow(ConfigurationService configService, Action<DeviceProfile> onSetActiveProfile)
        {
            InitializeComponent();
            DataContext = new ProfileManagementViewModel(configService, this, onSetActiveProfile);
        }

        public async Task<string?> ShowOpenFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType(fileType) { Patterns = new[] { $"*.{defaultExtension}" } } }
            });
            return files.Count == 1 ? files[0].TryGetLocalPath() : null;
        }

        public async Task<string?> OpenFolderPickerAsync(string title)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title });
            return folders.Count == 1 ? folders[0].TryGetLocalPath() : null;
        }

        public async Task<string?> OpenFilePickerAsync(string title)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = false });
            return files.Count == 1 ? files[0].TryGetLocalPath() : null;
        }

        public async Task<string?> ShowSaveFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = title,
                DefaultExtension = defaultExtension,
                FileTypeChoices = new[] { new FilePickerFileType(fileType) { Patterns = new[] { $"*.{defaultExtension}" } } }
            });
            return file?.TryGetLocalPath();
        }

        public async Task ShowMessageAsync(string title, string message)
        {
            var dialog = new Window
            {
                Title = title,
                Width = 400,
                Height = 200,
                Content = new TextBlock { Text = message, Margin = new Avalonia.Thickness(20) }
            };
            await dialog.ShowDialog(this);
        }

        public void ShowSocatLogWindow()
        {
            // This method is not applicable for ProfileManagementWindow
            // It's only used in the main window context
        }
    }
}
