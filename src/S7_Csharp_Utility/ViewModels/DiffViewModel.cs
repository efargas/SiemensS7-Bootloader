using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using Avalonia.Threading;
using System.Collections.ObjectModel;
using DiffPlex;
using DiffPlex.DiffBuilder;
using DiffPlex.DiffBuilder.Model;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// ViewModel for file comparison using DiffPlex to show line-by-line differences.
    /// </summary>
    public sealed class DiffViewModel : ViewModelBase, IDisposable
    {
        private readonly FileComparisonService _fileComparisonService;
        private readonly CancellationTokenSource _cancellationTokenSource;

        public ObservableCollection<DiffPiece> DiffLines { get; } = new ObservableCollection<DiffPiece>();

        private string _file1Info = string.Empty;
        public string File1Info
        {
            get => _file1Info;
            set => SetProperty(ref _file1Info, value);
        }

        private string _file2Info = string.Empty;
        public string File2Info
        {
            get => _file2Info;
            set => SetProperty(ref _file2Info, value);
        }

        private string _comparisonStatus = "Comparing files...";
        public string ComparisonStatus
        {
            get => _comparisonStatus;
            set => SetProperty(ref _comparisonStatus, value);
        }

        private bool _isLoading = true;
        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                if (_isLoading == value) return;
                _isLoading = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(NotLoading));
                if (RefreshCommand is AsyncRelayCommand arc) arc.RaiseCanExecuteChanged();
            }
        }

        public bool NotLoading => !IsLoading;

        private double _loadingProgress;
        public double LoadingProgress
        {
            get => _loadingProgress;
            set => SetProperty(ref _loadingProgress, value);
        }

        public ICommand RefreshCommand { get; }
        public string File1Path { get; }
        public string File2Path { get; }

        public DiffViewModel(string file1Path, string file2Path)
        {
            File1Path = file1Path ?? throw new ArgumentNullException(nameof(file1Path));
            File2Path = file2Path ?? throw new ArgumentNullException(nameof(file2Path));
            
            _fileComparisonService = new FileComparisonService();
            _cancellationTokenSource = new CancellationTokenSource();

            RefreshCommand = new AsyncRelayCommand(_ => LoadAndCompareFilesAsync(), _ => !IsLoading);

            _ = LoadAndCompareFilesAsync();
        }

        private async Task LoadAndCompareFilesAsync()
        {
            try
            {
                IsLoading = true;
                LoadingProgress = 0;
                ComparisonStatus = "Loading file information...";
                DiffLines.Clear();

                var file1InfoTask = _fileComparisonService.GetFileInfoAsync(File1Path, _cancellationTokenSource.Token);
                var file2InfoTask = _fileComparisonService.GetFileInfoAsync(File2Path, _cancellationTokenSource.Token);

                var fileInfos = await Task.WhenAll(file1InfoTask, file2InfoTask).ConfigureAwait(false);
                var file1Info = fileInfos[0];
                var file2Info = fileInfos[1];

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    File1Info = FormatFileInfo(file1Info);
                    File2Info = FormatFileInfo(file2Info);
                    LoadingProgress = 30;
                });

                if (string.Equals(file1Info.MD5Hash, file2Info.MD5Hash, StringComparison.OrdinalIgnoreCase))
                {
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        ComparisonStatus = "✅ Files are identical (same MD5 hash)";
                        DiffLines.Add(new DiffPiece("Files are identical.", ChangeType.Unchanged));
                        LoadingProgress = 100;
                        IsLoading = false;
                    });
                    return;
                }

                ComparisonStatus = "Files differ. Generating diff...";
                LoadingProgress = 60;

                var text1 = await File.ReadAllTextAsync(File1Path, _cancellationTokenSource.Token);
                var text2 = await File.ReadAllTextAsync(File2Path, _cancellationTokenSource.Token);

                var diffBuilder = new InlineDiffBuilder(new Differ());
                var diff = diffBuilder.BuildDiffModel(text1, text2);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    foreach (var line in diff.Lines)
                    {
                        DiffLines.Add(line);
                    }
                    ComparisonStatus = "✅ Comparison complete. Files differ.";
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
                    IsLoading = false;
                });
            }
        }

        private static string FormatFileInfo(FileComparisonService.FileInfo fileInfo)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"📁 File: {fileInfo.FileName}");
            sb.AppendLine($"📏 Size: {fileInfo.FormattedSize} ({fileInfo.FileSize:N0} bytes)");
            sb.AppendLine($"🔒 MD5: {fileInfo.MD5Hash.ToUpperInvariant()}");
            sb.AppendLine($"📅 Modified: {fileInfo.LastModified:yyyy-MM-dd HH:mm:ss}");
            return sb.ToString();
        }

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
        }
    }
}