using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System;
using System.IO;
using System.Threading.Tasks;
using S7.Utils;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main window of the application.
    /// </summary>
    public partial class MainWindow : Window, IDialogService
    {
        private readonly Services.PowerController _powerController;

        private readonly Services.LoggingService _loggingService;
        private readonly Services.SocatLoggerService _socatLoggerService;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();
            _loggingService = new Services.LoggingService(Dispatcher.UIThread);
            _socatLoggerService = new Services.SocatLoggerService(Dispatcher.UIThread);
            _powerController = new Services.PowerController((message, isError) => _loggingService.Log(message, isError ? Services.LogCategory.Error : Services.LogCategory.Info));
            var payloadManager = new S7.Net.PayloadManager(AppContext.BaseDirectory);
            var socatService = new Services.SocatService(_socatLoggerService);
            var configService = new Services.ConfigurationService();
            var viewModel = new ViewModels.MainWindowViewModel(_loggingService, _powerController, payloadManager, this, socatService, configService, _socatLoggerService);
            DataContext = viewModel;

            viewModel.LoadConfigurationOnStartup();
            Closing += (s, e) => viewModel.SaveConfigurationOnExit();

            MenuProfileManagement.Click += (s, e) =>
            {
                var vm = DataContext as ViewModels.MainWindowViewModel;
                if (vm != null)
                {
                    Action<DeviceProfile> onSetActiveProfile = (profile) =>
                    {
                        vm.LoadedProfile = profile;
                    };
                    new ProfileManagementWindow(vm.ConfigService, onSetActiveProfile).Show(this);
                }
            };
            MenuFirmwareUnpacker.Click += (s, e) => 
            {
                var vm = DataContext as ViewModels.MainWindowViewModel;
                string extractionPath = vm?.ExtractionPath ?? "";
                string resolvedPath = Models.ApplicationConfiguration.ResolvePath(extractionPath, Models.ApplicationConfiguration.GetDefaultExtractionPath());
                new FirmwareUnpackerWindow(resolvedPath, this).Show();
            };
            MenuHexViewer.Click += async (s, e) =>
            {
                var filePath = await OpenFilePickerAsync("Open file");
                if (!string.IsNullOrEmpty(filePath))
                {
                    new HexViewerWindow(filePath).Show();
                }
            };
            
            MenuExit.Click += (s, e) => Close();

            // --- Autoscroll Implementation ---
            var logListBox = this.FindControl<ListBox>("LogListBox");
            var socatLogListBox = this.FindControl<ListBox>("SocatLogListBox");

            _loggingService.ScrollToEnd += () =>
            {
                if (logListBox != null && logListBox.Items.Count > 0)
                {
                    // Defer the scroll operation to avoid layout issues
                    Dispatcher.UIThread.Post(() =>
                    {
                        try
                        {
                            var lastItem = logListBox.Items[logListBox.Items.Count - 1];
                            if (lastItem != null)
                            {
                                logListBox.ScrollIntoView(lastItem);
                            }
                        }
                        catch (Exception ex)
                        {
                            // Silently ignore scroll errors to prevent crashes
                            System.Diagnostics.Debug.WriteLine($"ScrollIntoView error: {ex.Message}");
                        }
                    }, Avalonia.Threading.DispatcherPriority.Background);
                }
            };

            _socatLoggerService.ScrollToEnd += () =>
            {
                if (socatLogListBox != null && socatLogListBox.Items.Count > 0)
                {
                    // Defer the scroll operation to avoid layout issues
                    Dispatcher.UIThread.Post(() =>
                    {
                        try
                        {
                            var lastItem = socatLogListBox.Items[socatLogListBox.Items.Count - 1];
                            if (lastItem != null)
                            {
                                socatLogListBox.ScrollIntoView(lastItem);
                            }
                        }
                        catch (Exception ex)
                        {
                            // Silently ignore scroll errors to prevent crashes
                            System.Diagnostics.Debug.WriteLine($"ScrollIntoView error: {ex.Message}");
                        }
                    }, Avalonia.Threading.DispatcherPriority.Background);
                }
            };
        }

        /// <summary>
        /// Checks if a ScrollViewer is scrolled to the bottom.
        /// </summary>
        /// <param name="sv">The ScrollViewer to check.</param>
        /// <returns>True if the ScrollViewer is at the bottom, false otherwise.</returns>
        private bool IsAtBottom(ScrollViewer sv)
        {
            const double tolerance = 1.0;
            return sv.Extent.Height - sv.Viewport.Height - sv.Offset.Y < tolerance;
        }

        /// <summary>
        /// Opens a folder picker dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <returns>The selected folder path, or null if no folder was selected.</returns>
        public async Task<string?> OpenFolderPickerAsync(string title)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title });
            return folders.Count == 1 ? folders[0].TryGetLocalPath() : null;
        }

        /// <summary>
        /// Opens a file picker dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
        public async Task<string?> OpenFilePickerAsync(string title)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return null;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = false });
            return files.Count == 1 ? files[0].TryGetLocalPath() : null;
        }

        /// <summary>
        /// Shows the socat log window.
        /// </summary>
        public void ShowSocatLogWindow()
        {
            var textBox = new TextBox
            {
                Text = _socatLoggerService.LogText,
                IsReadOnly = true,
                AcceptsReturn = true,
                FontFamily = "Consolas,Monospace"
            };
            ScrollViewer.SetVerticalScrollBarVisibility(textBox, ScrollBarVisibility.Auto);

            var logWindow = new Window
            {
                Title = "Socat Log",
                Width = 800,
                Height = 600,
                Content = textBox
            };
            logWindow.Show();
        }

        /// <summary>
        /// Shows a save file dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="defaultExtension">The default file extension.</param>
        /// <param name="fileType">The file type description.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
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

        /// <summary>
        /// Shows an open file dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="defaultExtension">The default file extension.</param>
        /// <param name="fileType">The file type description.</param>
        /// <returns>The selected file path, or null if no file was selected.</returns>
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

        /// <summary>
        /// Shows a message dialog.
        /// </summary>
        /// <param name="title">The title of the dialog.</param>
        /// <param name="message">The message to display.</param>
        public async Task ShowMessageAsync(string title, string message)
        {
            var dialog = new Window
            {
                Title = title,
                Width = 520,
                Height = 430,
                Content = new ScrollViewer
                {
                    Content = new TextBox { Text = message, IsReadOnly = true, AcceptsReturn = true, FontFamily = "Consolas,Monospace" }
                }
            };
            await dialog.ShowDialog(this);
        }

    }
}
