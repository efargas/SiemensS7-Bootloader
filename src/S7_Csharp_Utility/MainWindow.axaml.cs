
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

namespace S7_Csharp_Utility
{
    public partial class MainWindow : Window
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
            DataContext = new ViewModels.MainWindowViewModel(_loggingService, _powerController, plcClient, payloadManager);
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

            BrowseCompareFolderButton.Click += BrowseCompareFolderButton_Click;
            BrowseCompareFile1Button.Click += BrowseCompareFile1Button_Click;
            BrowseCompareFile2Button.Click += BrowseCompareFile2Button_Click;
            CompareDumpsButton.Click += CompareDumpsButton_Click;
            CompareTwoFilesButton.Click += CompareTwoFilesButton_Click;

            ClearLogButton.Click += (s, e) => _loggingService.Clear();
            ExportLogButton.Click += async (s, e) => await ExportLogFileAsync();
        }

        private bool IsAtBottom(ScrollViewer sv)
        {
            // Consider we're at the bottom if the viewport is within 2px of the end
            return sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 2;
        }

        #region Dump Comparison
        private async void BrowseCompareFolderButton_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Select Folder to Compare" });
            if (folders.Count == 1)
            {
                CompareFolderTextBox.Text = folders[0].Path.AbsolutePath;
            }
        }

        private async void BrowseCompareFile1Button_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Select File 1", AllowMultiple = false });
            if (files.Count == 1)
            {
                CompareFile1TextBox.Text = files[0].Path.AbsolutePath;
            }
        }

        private async void BrowseCompareFile2Button_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Select File 2", AllowMultiple = false });
            if (files.Count == 1)
            {
                CompareFile2TextBox.Text = files[0].Path.AbsolutePath;
            }
        }

        private async void CompareDumpsButton_Click(object? sender, RoutedEventArgs e)
        {
            string folder = CompareFolderTextBox.Text ?? string.Empty;
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                await ShowResultPopup("Please select a valid folder.");
                return;
            }
            //SetControlsEnabled(false);
            ComparisonResultsListBox.Items.Clear();
            try
            {
                var comparer = new DumpComparer(message => Dispatcher.UIThread.Post(() => _loggingService.Log(message)));
                var fileHashes = await comparer.ComputeFileHashesAsync(folder);
                string report = comparer.GenerateFolderCompareReport(fileHashes, folder);
                ComparisonResultsListBox.Items.Clear();
                foreach (var kv in fileHashes)
                {
                    string hash = kv.Key;
                    var files = kv.Value;
                    string prefix = files.Count == 1 ? "SINGLE" : "GROUP";
                    foreach (var file in files)
                    {
                        ComparisonResultsListBox.Items.Add($"{prefix} {Path.GetFileName(file)} [{hash.Substring(0, 8)}]");
                    }
                }
                await ShowResultPopup(report);
                _loggingService.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await ShowResultPopup($"Error: {ex.Message}");
                _loggingService.Log($"Error during folder compare: {ex.Message}", Services.LogCategory.Error);
            }
            finally
            {
                //SetControlsEnabled(true);
            }
        }

        private async void CompareTwoFilesButton_Click(object? sender, RoutedEventArgs e)
        {
            string fileA = CompareFile1TextBox.Text ?? string.Empty;
            string fileB = CompareFile2TextBox.Text ?? string.Empty;
            if (!File.Exists(fileA) || !File.Exists(fileB))
            {
                await ShowResultPopup("Please select two valid files.");
                return;
            }
            //SetControlsEnabled(false);
            FileCompareResultsListBox.Items.Clear();
            try
            {
                var comparer = new DumpComparer();
                string hashA = await comparer.ComputeFileHashAsync(fileA);
                string hashB = await comparer.ComputeFileHashAsync(fileB);
                bool match = hashA == hashB;
                var sb = new StringBuilder();
                sb.AppendLine($"File 1: {Path.GetFileName(fileA)}");
                sb.AppendLine($"MD5: {hashA}");
                sb.AppendLine($"File 2: {Path.GetFileName(fileB)}");
                sb.AppendLine($"MD5: {hashB}");
                sb.AppendLine(match ? "=> MATCH" : "=> DIFFER");
                FileCompareResultsListBox.Items.Add(match ? "MATCH" : "DIFFER");
                await ShowResultPopup(sb.ToString());
                _loggingService.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await ShowResultPopup($"Error: {ex.Message}");
                _loggingService.Log($"Error during file compare: {ex.Message}", Services.LogCategory.Error);
            }
            finally
            {
                //SetControlsEnabled(true);
            }
        }

        private async Task ShowResultPopup(string text)
        {
            var dialog = new Window
            {
                Title = "Comparison Result",
                Width = 520,
                Height = 430,
                Content = new ScrollViewer
                {
                    Content = new TextBox { Text = text, IsReadOnly = true, AcceptsReturn = true, FontFamily = "Consolas,Monospace", Watermark = "Comparison results..." }
                }
            };
            await dialog.ShowDialog(this);
        }
        #endregion
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
                var filtered = _logMessages.ToList();
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
