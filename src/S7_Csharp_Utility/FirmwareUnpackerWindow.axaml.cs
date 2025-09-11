using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace S7_Csharp_Utility
{
    public partial class FirmwareUnpackerWindow : Window
    {
        private S7UpdateUnpacker _unpacker = new S7UpdateUnpacker();
        private string _firmwarePath = "";
        public FirmwareUnpackerWindow()
        {
            InitializeComponent();
            SelectFirmwareButton.Click += SelectFirmwareButton_Click;
            UnpackFirmwareButton.Click += UnpackFirmwareButton_Click;
        }
        private async void SelectFirmwareButton_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select Firmware File",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("UPD Files") { Patterns = new[] { "*.upd" } } }
            });

            if (files.Count >= 1)
            {
                _firmwarePath = files[0].Path.AbsolutePath;
                FirmwareMetadataTextBlock.Text = "Parsing...";
                UnpackFirmwareButton.IsEnabled = false;
                try
                {
                    var metadata = _unpacker.ParseMetadata(_firmwarePath);
                    var sb = new StringBuilder();
                    sb.AppendLine($"Found {metadata.Count} components:");
                    foreach(var entry in metadata)
                        sb.AppendLine($" - Name: {entry.Name}, Size: {entry.Size}, CRC: {entry.Crc:X8}");
                    FirmwareMetadataTextBlock.Text = sb.ToString();
                    UnpackFirmwareButton.IsEnabled = true;
                } catch(Exception ex) {
                    FirmwareMetadataTextBlock.Text = $"Error: {ex.Message}";
                }
            }
        }
        private async void UnpackFirmwareButton_Click(object? sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_firmwarePath)) return;
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var folder = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select Destination Folder"
            });

            if (folder.Count >= 1)
            {
                string output = Path.Combine(folder[0].Path.AbsolutePath, Path.GetFileName(_firmwarePath) + ".unpacked.bin");
                try
                {
                    await Task.Run(() => _unpacker.Unpack(_firmwarePath, output));
                    await ShowMessage($"Unpacked to: {output}");
                } catch (Exception ex) { await ShowMessage($"Error: {ex.Message}"); }
            }
        }
        private async Task ShowMessage(string msg)
        {
            var dlg = new Window { Title = "Info", Content = new TextBlock { Text = msg, Margin = new Avalonia.Thickness(12) }, Width = 360, Height = 120 };
            await dlg.ShowDialog(this);
        }
    }
}
