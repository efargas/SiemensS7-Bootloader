using Avalonia.Controls;
using Avalonia.Platform.Storage;
using S7_Csharp_Utility.Interfaces;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    public class DialogService : IDialogService
    {
        private Window? _mainWindow;

        public DialogService()
        {
        }

        private Window GetMainWindow()
        {
            if (_mainWindow != null)
                return _mainWindow;

            // Try to get the main window from the application
            var app = Avalonia.Application.Current;
            if (app?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
            {
                _mainWindow = desktop.MainWindow;
                return _mainWindow ?? throw new System.InvalidOperationException("Main window not found");
            }

            throw new System.InvalidOperationException("Unable to get main window");
        }

        public async Task<string?> OpenFilePickerAsync(string title)
        {
            var mainWindow = GetMainWindow();
            var storageProvider = mainWindow.StorageProvider;

            var options = new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = new List<FilePickerFileType>
                {
                    FilePickerFileTypes.All
                }
            };

            var result = await storageProvider.OpenFilePickerAsync(options).ConfigureAwait(false);
            return result?.FirstOrDefault()?.Path.LocalPath;
        }

        public async Task<string?> OpenFolderPickerAsync(string title)
        {
            var mainWindow = GetMainWindow();
            var storageProvider = mainWindow.StorageProvider;

            var options = new FolderPickerOpenOptions
            {
                Title = title,
                AllowMultiple = false
            };

            var result = await storageProvider.OpenFolderPickerAsync(options).ConfigureAwait(false);
            return result?.FirstOrDefault()?.Path.LocalPath;
        }

        public async Task<string?> ShowOpenFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            var mainWindow = GetMainWindow();
            var storageProvider = mainWindow.StorageProvider;

            var fileTypes = new List<FilePickerFileType>();

            if (!string.IsNullOrEmpty(defaultExtension) && !string.IsNullOrEmpty(fileType))
            {
                fileTypes.Add(new FilePickerFileType(fileType)
                {
                    Patterns = new[] { $"*.{defaultExtension.TrimStart('.')}" }
                });
            }

            fileTypes.Add(FilePickerFileTypes.All);

            var options = new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = fileTypes
            };

            var result = await storageProvider.OpenFilePickerAsync(options).ConfigureAwait(false);
            return result?.FirstOrDefault()?.Path.LocalPath;
        }

        public async Task<string?> ShowSaveFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            var mainWindow = GetMainWindow();
            var storageProvider = mainWindow.StorageProvider;

            var fileTypes = new List<FilePickerFileType>();

            if (!string.IsNullOrEmpty(defaultExtension) && !string.IsNullOrEmpty(fileType))
            {
                fileTypes.Add(new FilePickerFileType(fileType)
                {
                    Patterns = new[] { $"*.{defaultExtension.TrimStart('.')}" }
                });
            }

            fileTypes.Add(FilePickerFileTypes.All);

            var options = new FilePickerSaveOptions
            {
                Title = title,
                FileTypeChoices = fileTypes
            };

            var result = await storageProvider.SaveFilePickerAsync(options).ConfigureAwait(false);
            return result?.Path.LocalPath;
        }

        public async Task ShowMessageAsync(string title, string message)
        {
            var mainWindow = GetMainWindow();

            var messageBox = new Window
            {
                Title = title,
                Width = 400,
                Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };

            var stackPanel = new StackPanel
            {
                Margin = new Avalonia.Thickness(20),
                Spacing = 20
            };

            var textBlock = new TextBlock
            {
                Text = message,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
            };

            var button = new Button
            {
                Content = "OK",
                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                Padding = new Avalonia.Thickness(20, 5)
            };

            button.Click += (s, e) => messageBox.Close();

            stackPanel.Children.Add(textBlock);
            stackPanel.Children.Add(button);
            messageBox.Content = stackPanel;

            await messageBox.ShowDialog(mainWindow).ConfigureAwait(false);
        }

        public void ShowSocatLogWindow()
        {
            // Implementation for showing socat log window
            // This would need to be implemented based on your specific requirements
        }
    }
}
