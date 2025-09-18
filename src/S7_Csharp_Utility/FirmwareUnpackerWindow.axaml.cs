using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using S7.Utils;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The firmware unpacker window.
    /// </summary>
    public partial class FirmwareUnpackerWindow : Window
    {
        private S7UpdateUnpacker _unpacker = new S7UpdateUnpacker();
        private string _firmwarePath = "";
        private string _extractionPath = "";
        
        /// <summary>
        /// Initializes a new instance of the <see cref="FirmwareUnpackerWindow"/> class.
        /// </summary>
        /// <param name="extractionPath">The configured extraction path. If null or empty, user will be prompted to select a folder.</param>
        public FirmwareUnpackerWindow(string? extractionPath = null)
        {
            InitializeComponent();
            _extractionPath = extractionPath ?? "";
            SelectFirmwareButton.Click += SelectFirmwareButton_Click;
            UnpackFirmwareButton.Click += UnpackFirmwareButton_Click;
        }
        /// <summary>
        /// Handles the Click event of the SelectFirmwareButton control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
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
                _firmwarePath = new Uri(files[0].Path.ToString()).LocalPath;
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
        /// <summary>
        /// Handles the Click event of the UnpackFirmwareButton control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
        private async void UnpackFirmwareButton_Click(object? sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_firmwarePath)) return;
            
            string destinationFolder;
            
            // Use configured extraction path if available, otherwise prompt user
            if (!string.IsNullOrWhiteSpace(_extractionPath))
            {
                // Ensure the extraction directory exists
                Directory.CreateDirectory(_extractionPath);
                destinationFolder = _extractionPath;
            }
            else
            {
                // Fallback to user selection if no configured path
                var topLevel = TopLevel.GetTopLevel(this);
                if (topLevel == null) return;
                var folder = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
                {
                    Title = "Select Destination Folder"
                });

                if (folder.Count < 1) return;
                destinationFolder = new Uri(folder[0].Path.ToString()).LocalPath;
            }

            string output = Path.Combine(destinationFolder, Path.GetFileName(_firmwarePath) + ".unpacked.bin");
            try
            {
                await Task.Run(() => _unpacker.Unpack(_firmwarePath, output));
                await ShowMessage($"Unpacked to: {output}");
            } 
            catch (Exception ex) 
            { 
                await ShowMessage($"Error: {ex.Message}"); 
            }
        }
        /// <summary>
        /// Shows a message dialog.
        /// </summary>
        /// <param name="msg">The message to show.</param>
        private async Task ShowMessage(string msg)
        {
            var dlg = new Window { Title = "Info", Content = new TextBlock { Text = msg, Margin = new Avalonia.Thickness(12) }, Width = 360, Height = 120 };
            await dlg.ShowDialog(this);
        }
    }
}
