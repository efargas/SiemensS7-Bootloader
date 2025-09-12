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
    public partial class MainWindow : Window, IDialogService
    {
        private readonly Services.PowerController _powerController;

        private readonly Services.LoggingService _loggingService;
        private readonly Services.SocatLoggerService _socatLoggerService;

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

            FilterInfoCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterInfo = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };
            FilterErrorCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterError = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };
            FilterDebugCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterDebug = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };

            MenuProfileManagement.Click += (s, e) => new ProfileManagementWindow().Show();
            MenuFirmwareUnpacker.Click += (s, e) => new FirmwareUnpackerWindow().Show();
            
            MenuSaveConfig.Click += (s, e) => viewModel.SaveConfigurationCommand.Execute(null);
            MenuLoadConfig.Click += (s, e) => viewModel.LoadConfigurationCommand.Execute(null);
            MenuExit.Click += (s, e) => Close();

            ClearLogButton.Click += (s, e) => _loggingService.Clear();
            ExportLogButton.Click += async (s, e) => await ExportLogToFileAsync(_loggingService.LogText, "Export Main Log");

            // --- Autoscroll Implementation ---
            var logScrollViewer = this.FindControl<ScrollViewer>("LogScrollViewer");
            var socatLogScrollViewer = this.FindControl<ScrollViewer>("SocatLogScrollViewer");
            var isAutoScroll = true;
            var isSocatAutoScroll = true;

            if (logScrollViewer != null)
            {
                logScrollViewer.ScrollChanged += (s, e) =>
                {
                    // Only update auto-scroll state if the user manually scrolled
                    if (e.OffsetDelta.Y != 0) isAutoScroll = IsAtBottom(logScrollViewer);
                };
            }

            if (socatLogScrollViewer != null)
            {
                socatLogScrollViewer.ScrollChanged += (s, e) =>
                {
                    // Only update auto-scroll state if the user manually scrolled
                    if (e.OffsetDelta.Y != 0) isSocatAutoScroll = IsAtBottom(socatLogScrollViewer);
                };
            }

            _loggingService.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(Services.LoggingService.LogText) && isAutoScroll)
                {
                    Dispatcher.UIThread.Post(() => logScrollViewer?.ScrollToEnd());
                }
            };

            _socatLoggerService.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(Services.SocatLoggerService.LogText) && isSocatAutoScroll)
                {
                    Dispatcher.UIThread.Post(() => socatLogScrollViewer?.ScrollToEnd());
                }
            };

            ScrollToEndButton.Click += (s, e) =>
            {
                isAutoScroll = true;
                logScrollViewer?.ScrollToEnd();
            };

            var socatScrollToEndButton = this.FindControl<Button>("SocatScrollToEndButton");
            if (socatScrollToEndButton != null)
            {
                socatScrollToEndButton.Click += (s, e) =>
                {
                    isSocatAutoScroll = true;
                    socatLogScrollViewer?.ScrollToEnd();
                };
            }
        }

        private bool IsAtBottom(ScrollViewer sv)
        {
            const double tolerance = 1.0;
            return sv.Extent.Height - sv.Viewport.Height - sv.Offset.Y < tolerance;
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
        private async Task ExportLogToFileAsync(string logContent, string dialogTitle)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = dialogTitle,
                DefaultExtension = "txt",
                FileTypeChoices = new[] { new FilePickerFileType("Text Files") { Patterns = new[] { "*.txt" } } }
            });

            if (file is not null)
            {
                await using var stream = await file.OpenWriteAsync();
                using var writer = new StreamWriter(stream);
                await writer.WriteAsync(logContent);
            }
        }
    }
}
