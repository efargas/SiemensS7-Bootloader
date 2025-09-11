
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

namespace S7_Csharp_Utility
{
    public partial class MainWindow : Window
    {
        private readonly PlcCommunicator _plc;
        private readonly S7UpdateUnpacker _unpacker;
        private bool _stagerInstalled = false;

        private readonly ObservableCollection<LogMessage> _logMessages = new ObservableCollection<LogMessage>();
        private readonly List<LogMessage> _allLogMessages = new List<LogMessage>();
        private const int MaxLogLines = 2000;
        private bool _autoScroll = true;
        private ScrollViewer? _logScrollViewer;

        private enum LogCategory { Info, Error, Debug }

        private class LogMessage
        {
            public DateTime Timestamp { get; set; }
            public LogCategory Category { get; set; }
            public string Message { get; set; } = string.Empty;
        }

        public MainWindow()
        {
            InitializeComponent();
            LogListBox.ItemsSource = _logMessages;

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

            FilterInfoCheckBox.IsCheckedChanged += (s, e) => UpdateLogFilter();
            FilterErrorCheckBox.IsCheckedChanged += (s, e) => UpdateLogFilter();
            FilterDebugCheckBox.IsCheckedChanged += (s, e) => UpdateLogFilter();

            MenuProfileManagement.Click += (s, e) => new ProfileManagementWindow().Show();
            MenuFirmwareUnpacker.Click += (s, e) => new FirmwareUnpackerWindow().Show();

            _plc = new PlcCommunicator((message) => Log(message, LogCategory.Info));
            _unpacker = new S7UpdateUnpacker();

            PowerOnButton.Click += async (s, e) => await SetPower(true);
            PowerOffButton.Click += async (s, e) => await SetPower(false);
            UploadStagerButton.Click += UploadStagerButton_Click;
            DumpMemoryButton.Click += DumpMemoryButton_Click;

            BrowseCompareFolderButton.Click += BrowseCompareFolderButton_Click;
            BrowseCompareFile1Button.Click += BrowseCompareFile1Button_Click;
            BrowseCompareFile2Button.Click += BrowseCompareFile2Button_Click;
            CompareDumpsButton.Click += CompareDumpsButton_Click;
            CompareTwoFilesButton.Click += CompareTwoFilesButton_Click;

            ClearLogButton.Click += (s, e) =>
            {
                _allLogMessages.Clear();
                UpdateLogFilter();
            };
            ExportLogButton.Click += async (s, e) => await ExportLogFileAsync();
        }

        private void UpdateLogFilter()
        {
            if (LogListBox == null) return;

            _logScrollViewer ??= LogListBox.FindDescendantOfType<ScrollViewer>();
            if (_logScrollViewer != null)
            {
                // Track whether the user is at bottom before we rebuild the filtered view
                _autoScroll = IsAtBottom(_logScrollViewer);
            }

            bool filterInfo = FilterInfoCheckBox?.IsChecked ?? true;
            bool filterError = FilterErrorCheckBox?.IsChecked ?? true;
            bool filterDebug = FilterDebugCheckBox?.IsChecked ?? true;

            _logMessages.Clear();
            foreach (var entry in _allLogMessages)
            {
                if ((filterInfo && entry.Category == LogCategory.Info)
                    || (filterError && entry.Category == LogCategory.Error)
                    || (filterDebug && entry.Category == LogCategory.Debug))
                {
                    _logMessages.Add(entry);
                }
            }

            if (_autoScroll)
            {
                var sv = _logScrollViewer;
                Dispatcher.UIThread.Post(() => sv?.ScrollToEnd(), DispatcherPriority.Background);
            }
        }

        // Helpers for log filtering and autoscroll
        private bool IsAtBottom(ScrollViewer sv)
        {
            // Consider we're at the bottom if the viewport is within 2px of the end
            return sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 2;
        }

        private bool PassesCurrentFilter(LogMessage m)
        {
            bool filterInfo = FilterInfoCheckBox?.IsChecked ?? true;
            bool filterError = FilterErrorCheckBox?.IsChecked ?? true;
            bool filterDebug = FilterDebugCheckBox?.IsChecked ?? true;

            return (filterInfo && m.Category == LogCategory.Info)
                || (filterError && m.Category == LogCategory.Error)
                || (filterDebug && m.Category == LogCategory.Debug);
        }

        private void OnNewLogEntry(LogMessage entry, LogMessage? removed)
        {
            _logScrollViewer ??= LogListBox.FindDescendantOfType<ScrollViewer>();

            // If an old message rolled off, remove it from the filtered view if present
            if (removed != null)
            {
                // Reference equality works: both lists contain the same LogMessage instances
                var idx = _logMessages.IndexOf(removed);
                if (idx >= 0)
                {
                    _logMessages.RemoveAt(idx);
                }
            }

            // Determine autoscroll based on current position before adding anything
            if (_logScrollViewer != null)
            {
                _autoScroll = IsAtBottom(_logScrollViewer);
            }

            // Append the new message if it passes current filters
            if (PassesCurrentFilter(entry))
            {
                _logMessages.Add(entry);
            }

            // Only scroll if user is at the bottom
            if (_autoScroll)
            {
                _logScrollViewer?.ScrollToEnd();
            }
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
            SetControlsEnabled(false);
            ComparisonResultsListBox.Items.Clear();
            try
            {
                var fileHashes = await Task.Run(() => ComputeFileHashes(folder));
                string report = GenerateFolderCompareReport(fileHashes, folder);
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
                Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await ShowResultPopup($"Error: {ex.Message}");
                Log($"Error during folder compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                SetControlsEnabled(true);
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
            SetControlsEnabled(false);
            FileCompareResultsListBox.Items.Clear();
            try
            {
                string hashA = await Task.Run(() => ComputeFileHash(fileA));
                string hashB = await Task.Run(() => ComputeFileHash(fileB));
                bool match = hashA == hashB;
                var sb = new StringBuilder();
                sb.AppendLine($"File 1: {Path.GetFileName(fileA)}");
                sb.AppendLine($"MD5: {hashA}");
                sb.AppendLine($"File 2: {Path.GetFileName(fileB)}");
                sb.AppendLine($"MD5: {hashB}");
                sb.AppendLine(match ? "=> MATCH" : "=> DIFFER");
                FileCompareResultsListBox.Items.Add(match ? "MATCH" : "DIFFER");
                await ShowResultPopup(sb.ToString());
                Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await ShowResultPopup($"Error: {ex.Message}");
                Log($"Error during file compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                SetControlsEnabled(true);
            }
        }

        private Dictionary<string, List<string>> ComputeFileHashes(string folderPath)
        {
            var hashes = new Dictionary<string, List<string>>();
            var files = Directory.GetFiles(folderPath, "*");
            using (var md5 = MD5.Create())
            {
                foreach (var file in files)
                {
                    Dispatcher.UIThread.Post(() => Log($"Hashing {Path.GetFileName(file)}..."));
                    using (var stream = File.OpenRead(file))
                    {
                        var hashBytes = md5.ComputeHash(stream);
                        string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                        if (!hashes.ContainsKey(hashString))
                        {
                            hashes[hashString] = new List<string>();
                        }
                        hashes[hashString].Add(file);
                    }
                }
            }
            return hashes;
        }

        private string GenerateFolderCompareReport(Dictionary<string, List<string>> hashes, string folderPath)
        {
            var allFiles = Directory.GetFiles(folderPath, "*");
            var fileToHash = new Dictionary<string, string>();
            foreach (var kv in hashes)
            {
                foreach (var f in kv.Value)
                {
                    fileToHash[Path.GetFileName(f)] = kv.Key;
                }
            }

            var sb = new StringBuilder();
            sb.AppendLine("Files and their MD5 hashes:");
            foreach (var filePath in allFiles)
            {
                var fileName = Path.GetFileName(filePath);
                if (fileToHash.TryGetValue(fileName, out var hash))
                {
                    sb.AppendLine($"{fileName} : {hash}");
                }
                else
                {
                    sb.AppendLine($"{fileName} : [error computing hash]");
                }
            }
            sb.AppendLine();
            sb.AppendLine("Groups by identical hash:");
            int groupNum = 1;
            foreach (var kv in hashes)
            {
                var hash = kv.Key;
                var flist = kv.Value;
                sb.AppendLine($"Group {groupNum++} (Hash: {hash}):");
                foreach (var fn in flist)
                {
                    sb.AppendLine($"  {fn}");
                }
            }
            return sb.ToString();
        }

        private string ComputeFileHash(string path)
        {
            using (var md5 = MD5.Create())
            using (var stream = File.OpenRead(path))
            {
                var hashBytes = md5.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
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

        private void Log(string message, LogCategory category = LogCategory.Info)
        {
            var entry = new LogMessage
            {
                Timestamp = DateTime.Now,
                Category = category,
                Message = message
            };
            _allLogMessages.Add(entry);
            LogMessage? removed = null;
            if (_allLogMessages.Count > MaxLogLines)
            {
                removed = _allLogMessages[0];
                _allLogMessages.RemoveAt(0);
            }
            Dispatcher.UIThread.Post(() => OnNewLogEntry(entry, removed));
            HandleLogFile(entry);
        }

        private void HandleLogFile(LogMessage entry)
        {
            string logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            string logFile = Path.Combine(logDir, "log.txt");
            long maxSize = 5 * 1024 * 1024; // 5 MB
            if (File.Exists(logFile) && new FileInfo(logFile).Length > maxSize)
            {
                int idx = 1;
                string newLogFile;
                do
                {
                    newLogFile = Path.Combine(logDir, $"log_{idx}.txt");
                    idx++;
                }
                while (File.Exists(newLogFile));
                File.Move(logFile, newLogFile);
            }
            File.AppendAllText(logFile, $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}{Environment.NewLine}");
        }

        private async Task SetPower(bool on)
        {
            string state = on ? "ON" : "OFF";
            Log($"Attempting to turn power {state}...", LogCategory.Info);

            try
            {
                string host = ModbusHostTextBox.Text ?? string.Empty;
                if (!int.TryParse(ModbusPortTextBox.Text, out int port))
                {
                    Log("Error: Invalid Modbus port.", LogCategory.Error);
                    return;
                }
                if (!ushort.TryParse(ModbusCoilTextBox.Text, out ushort coilAddress))
                {
                    Log("Error: Invalid Modbus coil address.", LogCategory.Error);
                    return;
                }

                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(host, port);
                    if (!client.Connected)
                    {
                        Log($"Error: Could not connect to Modbus host {host}:{port}.", LogCategory.Error);
                        return;
                    }

                    var factory = new ModbusFactory();
                    IModbusMaster master = factory.CreateMaster(client);

                    ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);

                    await master.WriteSingleCoilAsync(0, zeroBasedCoilAddress, on);
                    Log($"Successfully turned power {state}.", LogCategory.Info);
                }
            }
            catch (Exception ex)
            {
                Log($"Error controlling power: {ex.Message}", LogCategory.Error);
            }
        }

        private async void UploadStagerButton_Click(object? sender, RoutedEventArgs e)
        {
            SetControlsEnabled(false);
            try
            {
                await SetPower(false);
                int delaySeconds = (int)(DelayNumericUpDown.Value ?? 1);
                Log($"Waiting for {delaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(delaySeconds * 1000);
                await SetPower(true);

                await Task.Delay(50);

                await RunStagerSequenceAsync();
            }
            catch (Exception ex)
            {
                Log($"An error occurred during the stager sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                if (_plc.IsConnected)
                {
                    _plc.Disconnect();
                }
                SetControlsEnabled(true);
            }
        }

        private async Task RunStagerSequenceAsync()
        {
            _stagerInstalled = false;
            if (!int.TryParse(PlcPortTextBox.Text, out int port))
            {
                Log("Error: Invalid PLC port.", LogCategory.Error);
                return;
            }
            await _plc.ConnectAsync(PlcHostTextBox.Text ?? string.Empty, port);
            if (!_plc.IsConnected) return;

            if (await _plc.PerformHandshakeAsync())
            {
                await _plc.GetVersion();

                string stagerPath = Path.Combine(AppContext.BaseDirectory, "payloads", "stager", "stager.bin");
                if (!File.Exists(stagerPath))
                {
                    Log($"Error: Stager payload not found at {stagerPath}", LogCategory.Error);
                    return;
                }
                byte[] stagerPayload = await File.ReadAllBytesAsync(stagerPath);
                Log($"Loaded stager payload ({stagerPayload.Length} bytes).", LogCategory.Info);

                await _plc.InstallStager(stagerPayload);
                _stagerInstalled = true;
                Log("Stager is installed and ready.", LogCategory.Info);
            }
        }

        private async void DumpMemoryButton_Click(object? sender, RoutedEventArgs e)
        {
            if (!_stagerInstalled)
            {
                Log("Error: Stager is not installed. Please run 'Upload Stager' first.", LogCategory.Error);
                return;
            }

            if (!uint.TryParse((DumpAddressTextBox.Text ?? string.Empty).Replace("0x", ""), NumberStyles.HexNumber, CultureInfo.CurrentCulture, out uint address))
            {
                Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).", LogCategory.Error);
                return;
            }
            if (!uint.TryParse(DumpLengthTextBox.Text, out uint length) || length == 0)
            {
                Log("Error: Invalid dump length. Must be a positive number.", LogCategory.Error);
                return;
            }

            SetControlsEnabled(false);
            try
            {
                await RunDumpSequenceAsync(address, length);
            }
            catch (Exception ex)
            {
                Log($"An error occurred during the dump sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                SetControlsEnabled(true);
            }
        }

        private async Task RunDumpSequenceAsync(uint address, uint length)
        {
            Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);

            Dispatcher.UIThread.Post(() =>
            {
                DumpProgressBar.Value = 0;
                DumpPercentLabel.Text = "0%";
                DumpBytesLabel.Text = $"Read: 0 / {length} bytes";
                DumpTimeLabel.Text = "Elapsed: 0s | Remaining: calculating...";
            });


            string dumperPath = Path.Combine(AppContext.BaseDirectory, "payloads", "dump_mem", "build", "dump_mem.bin");
            if (!File.Exists(dumperPath))
            {
                Log($"Error: Dumper payload not found at {dumperPath}", LogCategory.Error);
                return;
            }
            byte[] dumperPayload = await File.ReadAllBytesAsync(dumperPath);
            Log($"Loaded dumper payload ({dumperPayload.Length} bytes).", LogCategory.Info);

            int dumperHookIndex = 0x1a;
            await _plc.InstallAddHookViaStager(0x10010100, dumperPayload, dumperHookIndex);
            Log("Memory dumper payload installed.", LogCategory.Info);

            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            BitConverter.GetBytes(address).CopyTo(args, 1);
            BitConverter.GetBytes(length).CopyTo(args, 5);

            await _plc.InvokeAddHook(dumperHookIndex, args);
            Log("Dump command sent. Receiving data...", LogCategory.Info);

            var stopwatch = Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                double percentage = (double)bytesRead / length * 100;
                stopwatch.Stop();
                double elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
                double bytesPerSecond = bytesRead / elapsedSeconds;
                double remainingSeconds = (bytesPerSecond > 0) ? (length - bytesRead) / bytesPerSecond : 0;
                stopwatch.Start();

                Dispatcher.UIThread.Post(() =>
                {
                    DumpProgressBar.Value = percentage;
                    DumpPercentLabel.Text = $"{percentage:F1}%";
                    DumpBytesLabel.Text = $"Read: {bytesRead} / {length} bytes";
                    DumpTimeLabel.Text = $"Elapsed: {elapsedSeconds:F0}s | Remaining: {remainingSeconds:F0}s";
                });
            });

            var dumpedData = await _plc.ReceiveMany(progress);
            stopwatch.Stop();

            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            await File.WriteAllBytesAsync(outFilename, dumpedData);
            Log($"Successfully dumped {dumpedData.Length} bytes to {outFilename} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        private void SetControlsEnabled(bool enabled)
        {
            PlcHostTextBox.IsEnabled = enabled;
            PlcPortTextBox.IsEnabled = enabled;
            ModbusHostTextBox.IsEnabled = enabled;
            ModbusPortTextBox.IsEnabled = enabled;
            ModbusCoilTextBox.IsEnabled = enabled;
            DelayNumericUpDown.IsEnabled = enabled;
            PowerOnButton.IsEnabled = enabled;
            PowerOffButton.IsEnabled = enabled;
            UploadStagerButton.IsEnabled = enabled;
            DumpAddressTextBox.IsEnabled = enabled;
            DumpLengthTextBox.IsEnabled = enabled;
            DumpMemoryButton.IsEnabled = enabled;
            RegionComboBox.IsEnabled = enabled;
            CompareDumpsButton.IsEnabled = enabled;
            ComparisonResultsListBox.IsEnabled = enabled;
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
