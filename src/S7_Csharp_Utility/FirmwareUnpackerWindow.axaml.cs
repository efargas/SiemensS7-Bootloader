using Avalonia.Controls;
using System.Threading.Tasks;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.ViewModels;
using Avalonia.Platform.Storage;
using System;

namespace S7_Csharp_Utility
{
    public partial class FirmwareUnpackerWindow : Window, IDialogService
    {
        public FirmwareUnpackerWindow(string? extractionPath = null)
        {
            InitializeComponent();
            DataContext = new FirmwareUnpackerViewModel(this, extractionPath);
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

        public Task<string?> OpenFilePickerAsync(string title) => throw new NotImplementedException();
        public void ShowSocatLogWindow() => throw new NotImplementedException();
    }
}
