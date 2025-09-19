using Avalonia.Controls;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// A window for displaying binary files in hexadecimal format.
    /// </summary>
    public partial class HexViewerWindow : Window
    {
        private readonly string _filePath;

        /// <summary>
        /// Initializes a new instance of the <see cref="HexViewerWindow"/> class.
        /// </summary>
        /// <param name="filePath">The path to the file to display.</param>
        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _filePath = filePath;
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
                    HexContent.Text = "Error: File not found";
                    return;
                }

                FilePathText.Text = $"File: {_filePath}";
                StatusText.Text = "Loading...";

                var fileInfo = new FileInfo(_filePath);
                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB limit
                {
                    StatusText.Text = "File too large (>10MB)";
                    HexContent.Text = "Error: File is too large to display (>10MB)";
                    return;
                }

                var content = await Task.Run(() => GenerateHexDisplay(_filePath));
                HexContent.Text = content;
                StatusText.Text = $"Loaded {fileInfo.Length} bytes";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error loading file";
                HexContent.Text = $"Error: {ex.Message}";
            }
        }

        /// <summary>
        /// Generates a hexadecimal display of the file content.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>A string containing the hex display.</returns>
        private static string GenerateHexDisplay(string filePath)
        {
            var sb = new StringBuilder();
            var buffer = new byte[16];
            var offset = 0;

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                int bytesRead;
                while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    // Offset column
                    sb.Append($"{offset:X8}  ");

                    // Hex bytes
                    for (int i = 0; i < 16; i++)
                    {
                        if (i < bytesRead)
                        {
                            sb.Append($"{buffer[i]:X2} ");
                        }
                        else
                        {
                            sb.Append("   ");
                        }

                        // Add extra space after 8 bytes
                        if (i == 7)
                        {
                            sb.Append(" ");
                        }
                    }

                    sb.Append(" |");

                    // ASCII representation
                    for (int i = 0; i < bytesRead; i++)
                    {
                        char c = (char)buffer[i];
                        if (c >= 32 && c <= 126) // Printable ASCII
                        {
                            sb.Append(c);
                        }
                        else
                        {
                            sb.Append('.');
                        }
                    }

                    sb.AppendLine("|");
                    offset += bytesRead;
                }
            }

            return sb.ToString();
        }
    }
}