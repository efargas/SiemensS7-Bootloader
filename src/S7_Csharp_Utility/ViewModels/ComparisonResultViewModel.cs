using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;

namespace S7_Csharp_Utility.ViewModels
{
    public class ComparisonResultViewModel : ViewModelBase
    {
        private readonly IDialogService? _dialogService;
        private string _comparisonResult;
        private string _originalResult;

        public string ComparisonResult
        {
            get => _comparisonResult;
            set => SetProperty(ref _comparisonResult, value);
        }

        private int _resultCount;
        public int ResultCount
        {
            get => _resultCount;
            set => SetProperty(ref _resultCount, value);
        }

        private int _totalFiles;
        public int TotalFiles
        {
            get => _totalFiles;
            set => SetProperty(ref _totalFiles, value);
        }

        private int _identicalFiles;
        public int IdenticalFiles
        {
            get => _identicalFiles;
            set => SetProperty(ref _identicalFiles, value);
        }

        private int _differentFiles;
        public int DifferentFiles
        {
            get => _differentFiles;
            set => SetProperty(ref _differentFiles, value);
        }

        private int _uniqueFilesA;
        public int UniqueFilesA
        {
            get => _uniqueFilesA;
            set => SetProperty(ref _uniqueFilesA, value);
        }

        private int _uniqueFilesB;
        public int UniqueFilesB
        {
            get => _uniqueFilesB;
            set => SetProperty(ref _uniqueFilesB, value);
        }

        private bool _showIdentical = true;
        public bool ShowIdentical
        {
            get => _showIdentical;
            set
            {
                if (SetProperty(ref _showIdentical, value))
                {
                    FilterResults();
                }
            }
        }

        private bool _showDifferent = true;
        public bool ShowDifferent
        {
            get => _showDifferent;
            set
            {
                if (SetProperty(ref _showDifferent, value))
                {
                    FilterResults();
                }
            }
        }

        private bool _showUnique = true;
        public bool ShowUnique
        {
            get => _showUnique;
            set
            {
                if (SetProperty(ref _showUnique, value))
                {
                    FilterResults();
                }
            }
        }

        public ICommand CopyToClipboardCommand { get; }
        public ICommand ExportToTextCommand { get; }
        public ICommand ExportToCsvCommand { get; }
        public ICommand CopySummaryCommand { get; }
        public ICommand RefreshCommand { get; }

        public ComparisonResultViewModel(string comparisonResult, IDialogService? dialogService = null)
        {
            _dialogService = dialogService;
            _originalResult = comparisonResult;
            _comparisonResult = comparisonResult;

            AnalyzeResults();

            CopyToClipboardCommand = new AsyncRelayCommand(_ => CopyToClipboardAsync());
            ExportToTextCommand = new AsyncRelayCommand(_ => ExportToTextAsync());
            ExportToCsvCommand = new AsyncRelayCommand(_ => ExportToCsvAsync());
            CopySummaryCommand = new AsyncRelayCommand(_ => CopySummaryAsync());
            RefreshCommand = new RelayCommand(_ => FilterResults());
        }

        private void AnalyzeResults()
        {
            if (string.IsNullOrEmpty(_originalResult))
            {
                ResultCount = 0;
                TotalFiles = 0;
                IdenticalFiles = 0;
                DifferentFiles = 0;
                UniqueFilesA = 0;
                UniqueFilesB = 0;
                return;
            }

            var lines = _originalResult.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            ResultCount = lines.Length;

            // Count different types of results
            IdenticalFiles = lines.Count(l => l.Contains("✅ IDENTICAL") || l.Contains("IDENTICAL"));
            DifferentFiles = lines.Count(l => l.Contains("❌ DIFFERENT") || l.Contains("DIFFERENT"));
            UniqueFilesA = lines.Count(l => l.Contains("🔵 UNIQUE A") || l.Contains("UNIQUE A"));
            UniqueFilesB = lines.Count(l => l.Contains("🔴 UNIQUE B") || l.Contains("UNIQUE B"));
            TotalFiles = IdenticalFiles + DifferentFiles + UniqueFilesA + UniqueFilesB;
        }

        private void FilterResults()
        {
            if (string.IsNullOrEmpty(_originalResult))
            {
                ComparisonResult = string.Empty;
                return;
            }

            var lines = _originalResult.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var filteredLines = lines.Where(line =>
            {
                if (!ShowIdentical && (line.Contains("✅ IDENTICAL") || line.Contains("IDENTICAL")))
                    return false;
                if (!ShowDifferent && (line.Contains("❌ DIFFERENT") || line.Contains("DIFFERENT")))
                    return false;
                if (!ShowUnique && (line.Contains("🔵 UNIQUE A") || line.Contains("UNIQUE A") ||
                                   line.Contains("🔴 UNIQUE B") || line.Contains("UNIQUE B")))
                    return false;
                return true;
            });

            ComparisonResult = string.Join('\n', filteredLines);
            ResultCount = filteredLines.Count();
        }

        private async Task CopyToClipboardAsync()
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                var clipboard = desktop.MainWindow?.Clipboard;
                if (clipboard != null)
                {
                    await clipboard.SetTextAsync(ComparisonResult);
                }
            }
        }

        private async Task ExportToTextAsync()
        {
            if (_dialogService == null) return;

            try
            {
                var filePath = await _dialogService.ShowSaveFileDialogAsync(
                    "Export Comparison Results",
                    "txt",
                    "Text Files");

                if (!string.IsNullOrEmpty(filePath))
                {
                    var content = new StringBuilder();
                    content.AppendLine("Folder Comparison Results");
                    content.AppendLine("========================");
                    content.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    content.AppendLine();
                    content.AppendLine("Statistics:");
                    content.AppendLine($"  Total Files: {TotalFiles}");
                    content.AppendLine($"  Identical: {IdenticalFiles}");
                    content.AppendLine($"  Different: {DifferentFiles}");
                    content.AppendLine($"  Unique A: {UniqueFilesA}");
                    content.AppendLine($"  Unique B: {UniqueFilesB}");
                    content.AppendLine();
                    content.AppendLine("Detailed Results:");
                    content.AppendLine("================");
                    content.AppendLine(ComparisonResult);

                    await File.WriteAllTextAsync(filePath, content.ToString());

                    if (_dialogService != null)
                    {
                        await _dialogService.ShowMessageAsync("Export Complete",
                            $"Results exported to:\n{filePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                if (_dialogService != null)
                {
                    await _dialogService.ShowMessageAsync("Export Error",
                        $"Failed to export results:\n{ex.Message}");
                }
            }
        }

        private async Task ExportToCsvAsync()
        {
            if (_dialogService == null) return;

            try
            {
                var filePath = await _dialogService.ShowSaveFileDialogAsync(
                    "Export Comparison Results as CSV",
                    "csv",
                    "CSV Files");

                if (!string.IsNullOrEmpty(filePath))
                {
                    var csv = new StringBuilder();
                    csv.AppendLine("Status,File,Details");

                    var lines = ComparisonResult.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 3)
                        {
                            var status = parts[1]; // IDENTICAL, DIFFERENT, etc.
                            var fileName = parts[2];
                            var details = parts.Length > 3 ? string.Join(" ", parts.Skip(3)) : "";

                            csv.AppendLine($"\"{status}\",\"{fileName}\",\"{details}\"");
                        }
                    }

                    await File.WriteAllTextAsync(filePath, csv.ToString());

                    if (_dialogService != null)
                    {
                        await _dialogService.ShowMessageAsync("Export Complete",
                            $"CSV exported to:\n{filePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                if (_dialogService != null)
                {
                    await _dialogService.ShowMessageAsync("Export Error",
                        $"Failed to export CSV:\n{ex.Message}");
                }
            }
        }

        private async Task CopySummaryAsync()
        {
            var summary = new StringBuilder();
            summary.AppendLine("📊 Folder Comparison Summary");
            summary.AppendLine($"Total Files: {TotalFiles}");
            summary.AppendLine($"✅ Identical: {IdenticalFiles}");
            summary.AppendLine($"❌ Different: {DifferentFiles}");
            summary.AppendLine($"🔵 Unique A: {UniqueFilesA}");
            summary.AppendLine($"🔴 Unique B: {UniqueFilesB}");

            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                var clipboard = desktop.MainWindow?.Clipboard;
                if (clipboard != null)
                {
                    await clipboard.SetTextAsync(summary.ToString());
                }
            }
        }
    }
}
