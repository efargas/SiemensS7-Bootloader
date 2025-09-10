using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using NModbus;
using System.Globalization;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.ObjectModel;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace S7_Csharp_Utility
{
    public partial class MainWindow : Window
    {
        private readonly PlcCommunicator _plc;
        private readonly S7UpdateUnpacker _unpacker;
        private bool _stagerInstalled = false;
        private DeviceProfile _currentProfile;
        private ObservableCollection<MemoryRegion> _profileRegions;
        private IStorageFile _selectedFirmwareFile;

        

        public MainWindow()
        {
            InitializeComponent();

            // Find controls by name
            PlcHostTextBox = this.FindControl<TextBox>("PlcHostTextBox");
            PlcPortTextBox = this.FindControl<TextBox>("PlcPortTextBox");
            ModbusHostTextBox = this.FindControl<TextBox>("ModbusHostTextBox");
            ModbusPortTextBox = this.FindControl<TextBox>("ModbusPortTextBox");
            ModbusCoilTextBox = this.FindControl<TextBox>("ModbusCoilTextBox");
            DelayNumericUpDown = this.FindControl<NumericUpDown>("DelayNumericUpDown");
            LogTextBox = this.FindControl<TextBox>("LogTextBox");
            ClearLogButton = this.FindControl<Button>("ClearLogButton");
            PowerOnButton = this.FindControl<Button>("PowerOnButton");
            PowerOffButton = this.FindControl<Button>("PowerOffButton");
            UploadStagerButton = this.FindControl<Button>("UploadStagerButton");
            DumpAddressTextBox = this.FindControl<TextBox>("DumpAddressTextBox");
            DumpLengthTextBox = this.FindControl<TextBox>("DumpLengthTextBox");
            DumpMemoryButton = this.FindControl<Button>("DumpMemoryButton");
            DumpProgressBar = this.FindControl<ProgressBar>("DumpProgressBar");
            DumpPercentLabel = this.FindControl<TextBlock>("DumpPercentLabel");
            DumpBytesLabel = this.FindControl<TextBlock>("DumpBytesLabel");
            DumpTimeLabel = this.FindControl<TextBlock>("DumpTimeLabel");
            ProfileModelNameTextBox = this.FindControl<TextBox>("ProfileModelNameTextBox");
            LoadProfileButton = this.FindControl<Button>("LoadProfileButton");
            SaveProfileButton = this.FindControl<Button>("SaveProfileButton");
            RegionsDataGrid = this.FindControl<DataGrid>("RegionsDataGrid");
            RegionComboBox = this.FindControl<ComboBox>("RegionComboBox");
            CompareDumpsButton = this.FindControl<Button>("CompareDumpsButton");
            ComparisonResultsListBox = this.FindControl<ListBox>("ComparisonResultsListBox");
            SelectFirmwareButton = this.FindControl<Button>("SelectFirmwareButton");
            FirmwareMetadataTextBlock = this.FindControl<TextBlock>("FirmwareMetadataTextBlock");
            UnpackFirmwareButton = this.FindControl<Button>("UnpackFirmwareButton");

            _plc = new PlcCommunicator(Log);
            _unpacker = new S7UpdateUnpacker();
            _currentProfile = new DeviceProfile();
            _profileRegions = new ObservableCollection<MemoryRegion>();
            RegionsDataGrid.ItemsSource = _profileRegions;

            // Wire up event handlers
            PowerOnButton.Click += async (s, e) => await SetPower(true);
            PowerOffButton.Click += async (s, e) => await SetPower(false);
            UploadStagerButton.Click += UploadStagerButton_Click;
            DumpMemoryButton.Click += DumpMemoryButton_Click;
            LoadProfileButton.Click += LoadProfileButton_Click;
            SaveProfileButton.Click += SaveProfileButton_Click;
            RegionComboBox.SelectionChanged += RegionComboBox_SelectionChanged;
            CompareDumpsButton.Click += CompareDumpsButton_Click;
            SelectFirmwareButton.Click += SelectFirmwareButton_Click;
            UnpackFirmwareButton.Click += UnpackFirmwareButton_Click;
            ClearLogButton.Click += (s, e) => LogTextBox.Text = string.Empty;
        }

        #region Firmware Unpacker
        private async void SelectFirmwareButton_Click(object sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select Firmware File",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("UPD Files") { Patterns = new[] { "*.upd" } } }
            });

            if (files.Count >= 1)
            {
                _selectedFirmwareFile = files[0];
                Log($"Selected firmware: {_selectedFirmwareFile.Name}");
                FirmwareMetadataTextBlock.Text = "Parsing metadata...";
                UnpackFirmwareButton.IsEnabled = false;

                try
                {
                    var metadata = _unpacker.ParseMetadata(_selectedFirmwareFile.Path.AbsolutePath);
                    var sb = new StringBuilder();
                    sb.AppendLine($"Found {metadata.Count} components:");
                    foreach (var entry in metadata)
                    {
                        sb.AppendLine($" - Name: {entry.Name}, Size: {entry.Size}, CRC: {entry.Crc:X8}");
                    }
                    FirmwareMetadataTextBlock.Text = sb.ToString();
                    UnpackFirmwareButton.IsEnabled = true;
                }
                catch (Exception ex)
                {
                    FirmwareMetadataTextBlock.Text = $"Error parsing metadata: {ex.Message}";
                    Log($"Error parsing metadata: {ex.Message}");
                }
            }
        }

        private async void UnpackFirmwareButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedFirmwareFile == null) return;

            var topLevel = TopLevel.GetTopLevel(this);
            var folder = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select Destination Folder"
            });

            if (folder.Count >= 1)
            {
                var destinationPath = folder[0].Path.AbsolutePath;
                var outputFilePath = Path.Combine(destinationPath, $"{_selectedFirmwareFile.Name}.unpacked.bin");
                Log($"Unpacking {_selectedFirmwareFile.Name} to {outputFilePath}...");
                SetControlsEnabled(false);

                try
                {
                    await Task.Run(() => _unpacker.Unpack(_selectedFirmwareFile.Path.AbsolutePath, outputFilePath));
                    Log("Firmware unpacked successfully.");
                }
                catch (Exception ex)
                {
                    Log($"Error unpacking firmware: {ex.Message}");
                }
                finally
                {
                    SetControlsEnabled(true);
                }
            }
        }
        #endregion

        #region Dump Comparison
        private async void CompareDumpsButton_Click(object sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select Folder with Dumps",
                AllowMultiple = false
            });

            if (folders.Count >= 1)
            {
                var selectedFolder = folders[0];
                Log($"Comparing dumps in: {selectedFolder.Path.AbsolutePath}...");
                SetControlsEnabled(false);
                ComparisonResultsListBox.Items.Clear();

                try
                {
                    var fileHashes = await Task.Run(() => ComputeFileHashes(selectedFolder.Path.AbsolutePath));

                    var results = new List<string>();
                    int groupNum = 1;
                    foreach (var entry in fileHashes.Where(kv => kv.Value.Count > 1))
                    {
                        var sb = new StringBuilder();
                        sb.Append($"Group {groupNum++} (Hash: {entry.Key.Substring(0, 12)}...): ");
                        sb.Append(string.Join(", ", entry.Value));
                        results.Add(sb.ToString());
                    }

                    Dispatcher.UIThread.Post(() =>
                    {
                        ComparisonResultsListBox.Items.Clear();
                        if (results.Any())
                        {
                            foreach(var item in results)
                                ComparisonResultsListBox.Items.Add(item);
                            Log($"Comparison complete. Found {results.Count} groups of identical dumps.");
                        }
                        else
                        {
                            Log("Comparison complete. No identical dumps found.");
                        }
                    });
                }
                catch (Exception ex)
                {
                    Log($"Error during dump comparison: {ex.Message}");
                }
                finally
                {
                    SetControlsEnabled(true);
                }
            }
        }

        private Dictionary<string, List<string>> ComputeFileHashes(string folderPath)
        {
            var hashes = new Dictionary<string, List<string>>();
            var files = Directory.GetFiles(folderPath, "*.bin");

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
                        hashes[hashString].Add(Path.GetFileName(file));
                    }
                }
            }
            return hashes;
        }

        #endregion

        #region Profile Management
        private async void LoadProfileButton_Click(object sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Open Profile File",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("JSON Profiles") { Patterns = new[] { "*.json" } } }
            });

            if (files.Count >= 1)
            {
                try
                {
                    await using var stream = await files[0].OpenReadAsync();
                    using var reader = new StreamReader(stream);
                    string json = await reader.ReadToEndAsync();
                    _currentProfile = JsonSerializer.Deserialize<DeviceProfile>(json);

                    ProfileModelNameTextBox.Text = _currentProfile.ModelName;
                    _profileRegions.Clear();
                    foreach (var region in _currentProfile.Regions)
                    {
                        _profileRegions.Add(region);
                    }
                    RegionComboBox.ItemsSource = _currentProfile.Regions.Select(r => r.Name).ToList();
                    Log($"Loaded profile: {_currentProfile.ModelName}");
                }
                catch (Exception ex)
                {
                    Log($"Error loading profile: {ex.Message}");
                }
            }
        }

        private async void SaveProfileButton_Click(object sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save Profile File",
                DefaultExtension = "json",
                FileTypeChoices = new[] { new FilePickerFileType("JSON Profiles") { Patterns = new[] { "*.json" } } }
            });

            if (file is not null)
            {
                var profileToSave = new DeviceProfile
                {
                    ModelName = ProfileModelNameTextBox.Text,
                    Regions = _profileRegions.ToList()
                };

                try
                {
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    string json = JsonSerializer.Serialize(profileToSave, options);
                    await File.WriteAllTextAsync(file.Path.AbsolutePath, json);
                    Log($"Profile saved to {file.Name}");
                }
                catch (Exception ex)
                {
                    Log($"Error saving profile: {ex.Message}");
                }
            }
        }

        private void RegionComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (RegionComboBox.SelectedItem is string selectedRegionName && _currentProfile != null)
            {
                var selectedRegion = _currentProfile.Regions.FirstOrDefault(r => r.Name == selectedRegionName);
                if (selectedRegion != null)
                {
                    DumpAddressTextBox.Text = selectedRegion.Address;
                    DumpLengthTextBox.Text = selectedRegion.Size.ToString();
                    Log($"Selected region: {selectedRegion.Name}");
                }
            }
        }
        #endregion

        private const int LogLineLimit = 500; // Max log lines to keep
        private void Log(string message)
        {
            Dispatcher.UIThread.Post(() =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                LogTextBox.Text += $"[{timestamp}] {message}{Environment.NewLine}";
                // Limit log lines
                var lines = LogTextBox.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                if (lines.Length > LogLineLimit)
                    LogTextBox.Text = string.Join(Environment.NewLine, lines.Skip(lines.Length - LogLineLimit));
                // Auto-scroll
                LogTextBox.CaretIndex = LogTextBox.Text?.Length ?? 0;
            });
        }

        private async Task SetPower(bool on)
        {
            string state = on ? "ON" : "OFF";
            Log($"Attempting to turn power {state}...");

            try
            {
                string host = ModbusHostTextBox.Text;
                if (!int.TryParse(ModbusPortTextBox.Text, out int port))
                {
                    Log("Error: Invalid Modbus port.");
                    return;
                }
                if (!ushort.TryParse(ModbusCoilTextBox.Text, out ushort coilAddress))
                {
                    Log("Error: Invalid Modbus coil address.");
                    return;
                }

                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(host, port);
                    if (!client.Connected)
                    {
                        Log($"Error: Could not connect to Modbus host {host}:{port}.");
                        return;
                    }

                    var factory = new ModbusFactory();
                    IModbusMaster master = factory.CreateMaster(client);

                    ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);

                    await master.WriteSingleCoilAsync(0, zeroBasedCoilAddress, on);
                    Log($"Successfully turned power {state}.");
                }
            }
            catch (Exception ex)
            {
                Log($"Error controlling power: {ex.Message}");
            }
        }

        private async void UploadStagerButton_Click(object sender, RoutedEventArgs e)
        {
            SetControlsEnabled(false);
            try
            {
                await SetPower(false);
                int delaySeconds = (int)(DelayNumericUpDown.Value ?? 1);
                Log($"Waiting for {delaySeconds} seconds before powering on...");
                await Task.Delay(delaySeconds * 1000);
                await SetPower(true);

                await Task.Delay(50);

                await RunStagerSequenceAsync();
            }
            catch (Exception ex)
            {
                Log($"An error occurred during the stager sequence: {ex.Message}");
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
                Log("Error: Invalid PLC port.");
                return;
            }
            await _plc.ConnectAsync(PlcHostTextBox.Text, port);
            if (!_plc.IsConnected) return;

            if (await _plc.PerformHandshakeAsync())
            {
                await _plc.GetVersion();

                string stagerPath = Path.Combine(AppContext.BaseDirectory, "payloads", "stager", "stager.bin");
                if (!File.Exists(stagerPath))
                {
                    Log($"Error: Stager payload not found at {stagerPath}");
                    return;
                }
                byte[] stagerPayload = await File.ReadAllBytesAsync(stagerPath);
                Log($"Loaded stager payload ({stagerPayload.Length} bytes).");

                await _plc.InstallStager(stagerPayload);
                _stagerInstalled = true;
                Log("Stager is installed and ready.");
            }
        }

        private async void DumpMemoryButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_stagerInstalled)
            {
                Log("Error: Stager is not installed. Please run 'Upload Stager' first.");
                return;
            }

            if (!uint.TryParse(DumpAddressTextBox.Text.Replace("0x", ""), NumberStyles.HexNumber, CultureInfo.CurrentCulture, out uint address))
            {
                Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).");
                return;
            }
            if (!uint.TryParse(DumpLengthTextBox.Text, out uint length) || length == 0)
            {
                Log("Error: Invalid dump length. Must be a positive number.");
                return;
            }

            SetControlsEnabled(false);
            try
            {
                await RunDumpSequenceAsync(address, length);
            }
            catch (Exception ex)
            {
                Log($"An error occurred during the dump sequence: {ex.Message}");
            }
            finally
            {
                SetControlsEnabled(true);
            }
        }

        private async Task RunDumpSequenceAsync(uint address, uint length)
        {
            Log($"Starting memory dump of {length} bytes from 0x{address:X8}...");

            // Reset progress UI
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
                Log($"Error: Dumper payload not found at {dumperPath}");
                return;
            }
            byte[] dumperPayload = await File.ReadAllBytesAsync(dumperPath);
            Log($"Loaded dumper payload ({dumperPayload.Length} bytes).");

            int dumperHookIndex = 0x1a;
            await _plc.InstallAddHookViaStager(0x10010100, dumperPayload, dumperHookIndex);
            Log("Memory dumper payload installed.");

            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            BitConverter.GetBytes(address).CopyTo(args, 1);
            BitConverter.GetBytes(length).CopyTo(args, 5);

            await _plc.InvokeAddHook(dumperHookIndex, args);
            Log("Dump command sent. Receiving data...");

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
            Log($"Successfully dumped {dumpedData.Length} bytes to {outFilename} in {stopwatch.Elapsed.TotalSeconds:F1}s.");
        }


        private void SetControlsEnabled(bool enabled)
        {
            // Disable all interactive controls
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
            ProfileModelNameTextBox.IsEnabled = enabled;
            LoadProfileButton.IsEnabled = enabled;
            SaveProfileButton.IsEnabled = enabled;
            RegionsDataGrid.IsEnabled = enabled;
            RegionComboBox.IsEnabled = enabled;
            CompareDumpsButton.IsEnabled = enabled;
            ComparisonResultsListBox.IsEnabled = enabled;
            SelectFirmwareButton.IsEnabled = enabled;
            UnpackFirmwareButton.IsEnabled = enabled;
        }
    }
}
