
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NModbus;
using S7.Utils;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility
{
    public partial class MainWindow : Window, IDialogService
    {
        private readonly S7UpdateUnpacker _unpacker;
        private readonly Services.PowerController _powerController;

        private readonly Services.LoggingService _loggingService;
        private bool _autoScroll = true;
        private ScrollViewer? _logScrollViewer;

        public MainWindow()
        {
            InitializeComponent();
            _loggingService = new Services.LoggingService(Dispatcher.UIThread);
            _powerController = new Services.PowerController((message, isError) => _loggingService.Log(message, isError ? Services.LogCategory.Error : Services.LogCategory.Info));
            var plcClient = new S7.Net.PlcClient(message => _loggingService.Log(message, Services.LogCategory.Info));
            var payloadManager = new S7.Net.PayloadManager(AppContext.BaseDirectory);
            DataContext = new ViewModels.MainWindowViewModel(_loggingService, _powerController, plcClient, payloadManager, this);
            LogListBox.ItemsSource = _loggingService.LogMessages;

            _logScrollViewer = LogListBox.FindDescendantOfType<ScrollViewer>();
            if (_logScrollViewer != null)
            {
                _autoScroll = true;
                _logScrollViewer.ScrollChanged += (s, e) =>
                {
                    _autoScroll = IsAtBottom(_logScrollViewer);
                };
            }

            LogListBox.PointerWheelChanged += (s, e) =>
            {
                if (_logScrollViewer != null)
                {
                    _autoScroll = IsAtBottom(_logScrollViewer);
                }
            };

            ScrollToEndButton.Click += (s, e) =>
            {
                _autoScroll = true;
                var scrollViewer = LogListBox.FindDescendantOfType<ScrollViewer>();
                scrollViewer?.ScrollToEnd();
            };

            FilterInfoCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterInfo = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };
            FilterErrorCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterError = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };
            FilterDebugCheckBox.IsCheckedChanged += (s, e) => { if(s is CheckBox cb) _loggingService.FilterDebug = cb.IsChecked ?? false; _loggingService.UpdateLogFilter(); };

            MenuProfileManagement.Click += (s, e) => new ProfileManagementWindow().Show();
            MenuFirmwareUnpacker.Click += (s, e) => new FirmwareUnpackerWindow().Show();

            _unpacker = new S7UpdateUnpacker();

            ClearLogButton.Click += (s, e) => _loggingService.Clear();
            ExportLogButton.Click += async (s, e) => await ExportLogFileAsync();
        }

        private bool IsAtBottom(ScrollViewer sv)
        {
            // Consider we're at the bottom if the viewport is within 2px of the end
            return sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 2;
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
        private async Task ExportLogFileAsync()
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export Logs",
                DefaultExtension = "txt",
                FileTypeChoices = new[] { new FilePickerFileType("Text Files") { Patterns = new[] { "*.txt" } } }
            });

            if (file is not null)
            {
                var filtered = _loggingService.LogMessages.ToList();
                var sb = new StringBuilder();
                foreach (var msg in filtered)
                {
                    sb.AppendLine($"[{msg.Timestamp:yyyy-MM-dd HH:mm:ss}] {msg.Category} {msg.Message}");
                }
                await using var stream = await file.OpenWriteAsync();
                using var writer = new StreamWriter(stream);
                await writer.WriteAsync(sb.ToString());
            }
        }
    }
}
