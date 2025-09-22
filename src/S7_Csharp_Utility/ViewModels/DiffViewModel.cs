using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using Avalonia.Threading;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// ViewModel for optimized file comparison with chunked loading and MD5 hash display.
    /// Supports large files without blocking the UI thread.
    /// </summary>
    public sealed class DiffViewModel : ViewModelBase, IDisposable
    {
        private readonly FileComparisonService _fileComparisonService;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private const int MaxPreviewSize = 1024 * 1024; // 1MB preview limit

        private string _file1Text = "Loading...";
        /// <summary>
        /// Gets or sets the text content of the first file.
        /// </summary>
        public string File1Text
        {
            get => _file1Text;
            set { _file1Text = value; OnPropertyChanged(); }
        }

        private string _file2Text = "Loading...";
        /// <summary>
        /// Gets or sets the text content of the second file.
        /// </summary>
        public string File2Text
        {
            get => _file2Text;
            set { _file2Text = value; OnPropertyChanged(); }
        }

        private string _file1Info = string.Empty;
        /// <summary>
        /// Gets or sets the information about the first file (name, size, MD5).
        /// </summary>
        public string File1Info
        {
            get => _file1Info;
            set { _file1Info = value; OnPropertyChanged(); }
        }

        private string _file2Info = string.Empty;
        /// <summary>
        /// Gets or sets the information about the second file (name, size, MD5).
        /// </summary>
        public string File2Info
        {
            get => _file2Info;
            set { _file2Info = value; OnPropertyChanged(); }
        }

        private string _comparisonStatus = "Comparing files...";
        /// <summary>
        /// Gets or sets the comparison status message.
        /// </summary>
        public string ComparisonStatus
        {
            get => _comparisonStatus;
            set { _comparisonStatus = value; OnPropertyChanged(); }
        }

        private bool _isLoading = true;
        /// <summary>
        /// Gets or sets a value indicating whether the files are currently being loaded.
        /// </summary>
        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                if (_isLoading == value) return;
                _isLoading = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(NotLoading));
                // Update command availability when loading state changes
                if (RefreshCommand is AsyncRelayCommand arc1) arc1.RaiseCanExecuteChanged();
                if (ExportCommand is AsyncRelayCommand arc2) arc2.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Convenience property for XAML bindings that need the negated loading state.
        /// </summary>
        public bool NotLoading => !IsLoading;

        private bool _filesAreIdentical;
        /// <summary>
        /// Gets or sets a value indicating whether the files are identical.
        /// </summary>
        public bool FilesAreIdentical
        {
            get => _filesAreIdentical;
            set
            {
                if (_filesAreIdentical == value) return;
                _filesAreIdentical = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(NotFilesAreIdentical));
            }
        }

        /// <summary>
        /// Convenience property for XAML bindings to show when files differ.
        /// </summary>
        public bool NotFilesAreIdentical => !FilesAreIdentical;

        private double _loadingProgress;
        /// <summary>
        /// Gets or sets the loading progress percentage.
        /// </summary>
        public double LoadingProgress
        {
            get => _loadingProgress;
            set { _loadingProgress = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Gets the command to refresh the comparison.
        /// </summary>
        public ICommand RefreshCommand { get; }

        /// <summary>
        /// Gets the command to export the comparison results.
        /// </summary>
        public ICommand ExportCommand { get; }

        /// <summary>
        /// Gets the path to the first file.
        /// </summary>
        public string File1Path { get; }

        /// <summary>
        /// Gets the path to the second file.
        /// </summary>
        public string File2Path { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiffViewModel"/> class.
        /// </summary>
        /// <param name="file1Path">The path to the first file.</param>
        /// <param name="file2Path">The path to the second file.</param>
        public DiffViewModel(string file1Path, string file2Path)
        {
            File1Path = file1Path ?? throw new ArgumentNullException(nameof(file1Path));
            File2Path = file2Path ?? throw new ArgumentNullException(nameof(file2Path));
            
            _fileComparisonService = new FileComparisonService();
            _cancellationTokenSource = new CancellationTokenSource();

            RefreshCommand = new AsyncRelayCommand(_ => LoadFilesAsync(), _ => !IsLoading);
            ExportCommand = new AsyncRelayCommand(_ => ExportComparisonAsync(), _ => !IsLoading);

            // Start loading files asynchronously
            _ = LoadFilesAsync();
        }

        /// <summary>
        /// Loads and compares the files asynchronously.
        /// </summary>
        private async Task LoadFilesAsync()
        {
            try
            {
                IsLoading = true;
                LoadingProgress = 0;
                ComparisonStatus = "Loading file information...";

                // Load file information with progress reporting
                var progress1 = new Progress<long>(bytes => 
                {
                    Dispatcher.UIThread.Post(() => LoadingProgress = Math.Min(25, (bytes / 1024.0 / 1024.0) * 10));
                });
                
                var progress2 = new Progress<long>(bytes => 
                {
                    Dispatcher.UIThread.Post(() => LoadingProgress = Math.Min(50, 25 + (bytes / 1024.0 / 1024.0) * 10));
                });

                var file1InfoTask = _fileComparisonService.GetFileInfoAsync(File1Path, _cancellationTokenSource.Token, progress1);
                var file2InfoTask = _fileComparisonService.GetFileInfoAsync(File2Path, _cancellationTokenSource.Token, progress2);

                var fileInfos = await Task.WhenAll(file1InfoTask, file2InfoTask).ConfigureAwait(false);
                var file1Info = fileInfos[0];
                var file2Info = fileInfos[1];

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    File1Info = FormatFileInfo(file1Info);
                    File2Info = FormatFileInfo(file2Info);
                    LoadingProgress = 60;
                });

                // Check if files are identical
                FilesAreIdentical = string.Equals(file1Info.MD5Hash, file2Info.MD5Hash, StringComparison.OrdinalIgnoreCase);
                
                if (FilesAreIdentical)
                {
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        ComparisonStatus = "✅ Files are identical (same MD5 hash)";
                        File1Text = "Files are identical - no differences to display.";
                        File2Text = "Files are identical - no differences to display.";
                        LoadingProgress = 100;
                        IsLoading = false;
                    });
                    return;
                }

                ComparisonStatus = "Files differ - loading preview...";
                LoadingProgress = 70;

                // Load file previews (limited size for performance)
                await LoadFilePreviewsAsync(file1Info, file2Info);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = "✅ Comparison complete - Files differ (MD5 mismatch)";
                    LoadingProgress = 100;
                    IsLoading = false;
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = "❌ Comparison cancelled";
                    IsLoading = false;
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = $"❌ Error: {ex.Message}";
                    File1Text = $"Error loading file: {ex.Message}";
                    File2Text = $"Error loading file: {ex.Message}";
                    IsLoading = false;
                });
            }
        }

        /// <summary>
        /// Loads file previews for comparison display.
        /// </summary>
        private async Task LoadFilePreviewsAsync(FileComparisonService.FileInfo file1Info, FileComparisonService.FileInfo file2Info)
        {
            var previewSize = Math.Min(MaxPreviewSize, Math.Max(file1Info.FileSize, file2Info.FileSize));
            
            if (file1Info.FileSize > MaxPreviewSize || file2Info.FileSize > MaxPreviewSize)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = $"⚠️ Large files detected - showing first {previewSize / 1024}KB only";
                });
            }

            var chunk1Task = _fileComparisonService.ReadFileChunkAsync(File1Path, 0, (int)previewSize, _cancellationTokenSource.Token);
            var chunk2Task = _fileComparisonService.ReadFileChunkAsync(File2Path, 0, (int)previewSize, _cancellationTokenSource.Token);

            var chunks = await Task.WhenAll(chunk1Task, chunk2Task).ConfigureAwait(false);

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                File1Text = chunks[0].HexData;
                File2Text = chunks[1].HexData;
                LoadingProgress = 90;
            });
        }

        /// <summary>
        /// Formats file information for display.
        /// </summary>
        private static string FormatFileInfo(FileComparisonService.FileInfo fileInfo)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"📁 File: {fileInfo.FileName}");
            sb.AppendLine($"📏 Size: {fileInfo.FormattedSize} ({fileInfo.FileSize:N0} bytes)");
            sb.AppendLine($"🔒 MD5: {fileInfo.MD5Hash.ToUpperInvariant()}");
            sb.AppendLine($"📅 Modified: {fileInfo.LastModified:yyyy-MM-dd HH:mm:ss}");
            return sb.ToString();
        }

        /// <summary>
        /// Exports the comparison results to a text file.
        /// </summary>
        private async Task ExportComparisonAsync()
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var exportPath = Path.Combine(Path.GetTempPath(), $"file_comparison_{timestamp}.txt");

                var sb = new StringBuilder();
                sb.AppendLine("File Comparison Report");
                sb.AppendLine("======================");
                sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine();
                sb.AppendLine("File 1 Information:");
                sb.AppendLine(File1Info);
                sb.AppendLine();
                sb.AppendLine("File 2 Information:");
                sb.AppendLine(File2Info);
                sb.AppendLine();
                sb.AppendLine($"Comparison Result: {ComparisonStatus}");
                sb.AppendLine();
                
                if (!FilesAreIdentical)
                {
                    sb.AppendLine("File 1 Preview:");
                    sb.AppendLine(File1Text);
                    sb.AppendLine();
                    sb.AppendLine("File 2 Preview:");
                    sb.AppendLine(File2Text);
                }

                await File.WriteAllTextAsync(exportPath, sb.ToString()).ConfigureAwait(false);
                
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = $"✅ Report exported to: {exportPath}";
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    ComparisonStatus = $"❌ Export failed: {ex.Message}";
                });
            }
        }

        /// <summary>
        /// Disposes of resources used by the ViewModel.
        /// </summary>
        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
        }
    }
}