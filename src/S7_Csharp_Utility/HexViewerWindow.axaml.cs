using Avalonia.Controls;
using Avalonia.Platform.Storage;
using S7_Csharp_Utility.Commands;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace S7_Csharp_Utility
{
    public class HexViewRow
    {
        public string Offset { get; set; }
        public string Hex { get; set; }
        public string Ascii { get; set; }
    }

    /// <summary>
    /// A window for displaying binary files in hexadecimal format.
    /// </summary>
    public partial class HexViewerWindow : Window
    {
        private readonly string _filePath;
        public ObservableCollection<HexViewRow> HexData { get; } = new ObservableCollection<HexViewRow>();
        public ICommand ExportSelectionCommand { get; }
        public ICommand SearchCommand { get; }
        public string SearchText { get; set; } = "";

        /// <summary>
        /// Initializes a new instance of the <see cref="HexViewerWindow"/> class.
        /// </summary>
        /// <param name="filePath">The path to the file to display.</param>
        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _filePath = filePath;
            DataContext = this;
            ExportSelectionCommand = new AsyncRelayCommand(ExportSelectionAsync, _ => HexContent.SelectedItems.Count > 0);
            SearchCommand = new AsyncRelayCommand(SearchAsync, _ => !string.IsNullOrWhiteSpace(SearchText));
            HexContent.SelectionChanged += (s, e) => ((AsyncRelayCommand)ExportSelectionCommand).RaiseCanExecuteChanged();
            LoadFileAsync();
        }

        /// <summary>
        /// Loads and displays the file content in hexadecimal format.
        /// </summary>
        private async void LoadFileAsync()
        {
            try
            {
                if (!File.Exists(_filePath))
                {
                    StatusText.Text = "File not found";
                    return;
                }

                FilePathText.Text = $"File: {_filePath}";
                StatusText.Text = "Loading...";

                var fileInfo = new FileInfo(_filePath);
                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB limit
                {
                    StatusText.Text = "File too large (>10MB)";
                    return;
                }

                var hexRows = await Task.Run(() => GenerateHexRows(_filePath));

                HexData.Clear();
                foreach (var row in hexRows)
                {
                    HexData.Add(row);
                }

                StatusText.Text = $"Loaded {fileInfo.Length} bytes";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error loading file";
            }
        }

        /// <summary>
        /// Generates a hexadecimal display of the file content.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>A string containing the hex display.</returns>
        private static List<HexViewRow> GenerateHexRows(string filePath)
        {
            var rows = new List<HexViewRow>();
            var buffer = new byte[16];
            long offset = 0;

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                int bytesRead;
                while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    var hex = new StringBuilder();
                    var ascii = new StringBuilder();

                    // Hex bytes
                    for (int i = 0; i < 16; i++)
                    {
                        if (i < bytesRead)
                        {
                            hex.Append($"{buffer[i]:X2} ");
                        }
                        else
                        {
                            hex.Append("   ");
                        }

                        // Add extra space after 8 bytes
                        if (i == 7)
                        {
                            hex.Append(" ");
                        }
                    }

                    // ASCII representation
                    for (int i = 0; i < bytesRead; i++)
                    {
                        char c = (char)buffer[i];
                        if (c >= 32 && c <= 126) // Printable ASCII
                        {
                            ascii.Append(c);
                        }
                        else
                        {
                            ascii.Append('.');
                        }
                    }
                    rows.Add(new HexViewRow { Offset = $"{offset:X8}", Hex = hex.ToString(), Ascii = ascii.ToString() });
                    offset += bytesRead;
                }
            }

            return rows;
        }

        private async Task ExportSelectionAsync()
        {
            if (HexContent.SelectedItems.Count == 0)
            {
                return;
            }

            var storageProvider = this.StorageProvider;
            if (storageProvider == null)
            {
                StatusText.Text = "Cannot save file. Storage provider not available.";
                return;
            }

            var file = await storageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export Selection",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("Text File") { Patterns = new[] { "*.txt" } },
                    new FilePickerFileType("Binary File") { Patterns = new[] { "*.bin" } }
                }
            });

            if (file != null)
            {
                var selectedRows = HexContent.SelectedItems.Cast<HexViewRow>().ToList();
                selectedRows.Sort((a, b) => string.Compare(a.Offset, b.Offset, StringComparison.Ordinal));

                try
                {
                    await using var stream = await file.OpenWriteAsync();
                    if (file.Name.EndsWith(".txt"))
                    {
                        var sb = new StringBuilder();
                        foreach (var row in selectedRows)
                        {
                            sb.AppendLine($"{row.Offset}  {row.Hex} |{row.Ascii}|");
                        }
                        using (var writer = new StreamWriter(stream))
                        {
                            await writer.WriteAsync(sb.ToString());
                        }
                    }
                    else // .bin
                    {
                        var bytesToWrite = new List<byte>();
                        foreach (var row in selectedRows)
                        {
                            var hexBytes = row.Hex.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var hexByte in hexBytes)
                            {
                                if (byte.TryParse(hexByte, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                                {
                                    bytesToWrite.Add(b);
                                }
                            }
                        }
                        await stream.WriteAsync(bytesToWrite.ToArray());
                    }
                    StatusText.Text = $"Exported {selectedRows.Count} rows to {file.Name}";
                }
                catch (Exception ex)
                {
                    StatusText.Text = $"Error exporting file: {ex.Message}";
                }
            }
        }

        private async Task SearchAsync()
        {
            StatusText.Text = "Searching...";
            var pattern = HexStringToByteArray(SearchText);
            if (pattern == null || pattern.Length == 0)
            {
                StatusText.Text = "Invalid search pattern.";
                return;
            }

            long position = -1;
            await Task.Run(() =>
            {
                using (var fs = new FileStream(_filePath, FileMode.Open, FileAccess.Read))
                {
                    position = FindPattern(fs, pattern);
                }
            });

            if (position != -1)
            {
                StatusText.Text = $"Pattern found at offset 0x{position:X8}";
                var rowIndex = (int)(position / 16);
                if (rowIndex >= 0 && rowIndex < HexData.Count)
                {
                    HexContent.SelectedItem = HexData[rowIndex];
                    HexContent.ScrollIntoView(HexData[rowIndex], null);
                }
            }
            else
            {
                StatusText.Text = "Pattern not found.";
            }
        }

        private static byte[]? HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                return null;

            try
            {
                return Enumerable.Range(0, hex.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                 .ToArray();
            }
            catch
            {
                return null;
            }
        }

        private static long FindPattern(Stream stream, byte[] pattern)
        {
            if (pattern.Length == 0) return -1;

            long position = -1;
            const int bufferSize = 4096;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;
            long streamPosition = 0;

            byte[] searchBuffer = new byte[bufferSize + pattern.Length - 1];
            int searchBufferOffset = pattern.Length - 1;

            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                Buffer.BlockCopy(buffer, 0, searchBuffer, searchBufferOffset, bytesRead);
                int searchBufferLength = bytesRead + searchBufferOffset;

                for (int i = 0; i <= searchBufferLength - pattern.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        if (searchBuffer[i + j] != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                    {
                        position = streamPosition - searchBufferOffset + i;
                        return position;
                    }
                }

                streamPosition += bytesRead;
                Buffer.BlockCopy(buffer, bytesRead - searchBufferOffset, searchBuffer, 0, searchBufferOffset);
            }

            return position;
        }
    }
}