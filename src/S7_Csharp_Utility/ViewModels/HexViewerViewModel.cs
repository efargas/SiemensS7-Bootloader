#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using Avalonia;
using Avalonia.Threading;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using S7_Csharp_Utility.Models;

namespace S7_Csharp_Utility.ViewModels
{
    public sealed class HexViewerViewModel : ViewModelBase, IDisposable
    {
        private readonly HexViewerService _hexViewerService;
        private readonly IDialogService _dialogService;
        private CancellationTokenSource _cancellationTokenSource;

        private IList<HexViewerService.HexRow>? _hexRows1;
        public IList<HexViewerService.HexRow>? HexRows1
        {
            get => _hexRows1;
            set
            {
                _hexRows1 = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(HexRows)); // Notify that the alias property has changed too
            }
        }

        private IList<HexViewerService.HexRow>? _hexRows2;
        public IList<HexViewerService.HexRow>? HexRows2
        {
            get => _hexRows2;
            set
            {
                _hexRows2 = value;
                OnPropertyChanged();
            }
        }

        private string _file1Path = string.Empty;
        public string File1Path
        {
            get => _file1Path;
            set { _file1Path = value; OnPropertyChanged(); }
        }

        private string _file2Path = string.Empty;
        public string File2Path
        {
            get => _file2Path;
            set { _file2Path = value; OnPropertyChanged(); }
        }

        private string _file1Info = string.Empty;
        public string File1Info
        {
            get => _file1Info;
            set { _file1Info = value; OnPropertyChanged(); }
        }

        private string _file2Info = string.Empty;
        public string File2Info
        {
            get => _file2Info;
            set { _file2Info = value; OnPropertyChanged(); }
        }

        private bool _isSideBySideMode;
        public bool IsSideBySideMode
        {
            get => _isSideBySideMode;
            set
            {
                if (_isSideBySideMode != value)
                {
                    _isSideBySideMode = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(ShowSecondPanel));
                    SecondPanelWidth = value ? new GridLength(1, GridUnitType.Star) : new GridLength(0, GridUnitType.Pixel);
                    SeparatorWidth = value ? new GridLength(8, GridUnitType.Pixel) : new GridLength(0, GridUnitType.Pixel);
                    ((AsyncRelayCommand)LoadSecondFileCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public bool ShowSecondPanel => IsSideBySideMode;

        private GridLength _secondPanelWidth = new GridLength(0, GridUnitType.Pixel);
        public GridLength SecondPanelWidth
        {
            get => _secondPanelWidth;
            set { _secondPanelWidth = value; OnPropertyChanged(); }
        }

        private GridLength _inspectorWidth = new GridLength(350, GridUnitType.Pixel);
        public GridLength InspectorWidth
        {
            get => _inspectorWidth;
            set { _inspectorWidth = value; OnPropertyChanged(); }
        }

        private GridLength _separatorWidth = new GridLength(0, GridUnitType.Pixel);
        public GridLength SeparatorWidth
        {
            get => _separatorWidth;
            set { _separatorWidth = value; OnPropertyChanged(); }
        }

        private bool _isInspectorVisible = true;
        public bool IsInspectorVisible
        {
            get => _isInspectorVisible;
            set
            {
                if (_isInspectorVisible == value) return;
                _isInspectorVisible = value;
                OnPropertyChanged();
                InspectorWidth = value ? new GridLength(350, GridUnitType.Pixel) : new GridLength(0, GridUnitType.Pixel);
            }
        }

        private bool _isLoading;
        public bool IsLoading
        {
            get => _isLoading;
            set 
            { 
                _isLoading = value; 
                OnPropertyChanged(); 
                OnPropertyChanged(nameof(LoadingProgress));
            }
        }

        /// <summary>
        /// Gets the loading progress as a percentage (0-100).
        /// </summary>
        public double LoadingProgress => IsLoading ? 50.0 : 0.0; // Simplified progress indicator

        /// <summary>
        /// Gets the primary hex rows collection for single-file view compatibility.
        /// </summary>
        public IList<HexViewerService.HexRow>? HexRows => HexRows1;

        private string _statusText = "Ready";
        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        private bool _isLittleEndian = true;
        public bool IsLittleEndian
        {
            get => _isLittleEndian;
            set
            {
                _isLittleEndian = value;
                OnPropertyChanged();
                _ = UpdateInspectorPanelAsync();
            }
        }

        private bool _isSynchronizationEnabled = true;
        public bool IsSynchronizationEnabled
        {
            get => _isSynchronizationEnabled;
            set { _isSynchronizationEnabled = value; OnPropertyChanged(); }
        }

        private long _selectedOffset;
        public long SelectedOffset
        {
            get => _selectedOffset;
            set
            {
                _selectedOffset = value;
                OnPropertyChanged();
                _ = UpdateInspectorPanelAsync();
            }
        }

        private long _selectionStartOffset = -1;
        public long SelectionStartOffset
        {
            get => _selectionStartOffset;
            set
            {
                _selectionStartOffset = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SelectionLength));
            }
        }

        private long _selectionEndOffset = -1;
        public long SelectionEndOffset
        {
            get => _selectionEndOffset;
            set
            {
                _selectionEndOffset = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SelectionLength));
            }
        }

        public long SelectionLength
        {
            get
            {
                if (SelectionStartOffset >= 0 && SelectionEndOffset >= 0)
                {
                    return Math.Abs(SelectionEndOffset - SelectionStartOffset) + 1;
                }
                return 0;
            }
        }

        public bool IsOffsetInSelection(long offset)
        {
            if (SelectionStartOffset < 0 || SelectionEndOffset < 0) return false;
            var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
            var end = Math.Max(SelectionStartOffset, SelectionEndOffset);
            return offset >= start && offset <= end;
        }

        private HexViewerService.HexRow? _selectedRow;
        public HexViewerService.HexRow? SelectedRow
        {
            get => _selectedRow;
            set
            {
                _selectedRow = value;
                if (value != null)
                {
                    SelectedOffset = value.ByteOffset;
                }
                OnPropertyChanged();
            }
        }

        #region Search Properties
        private string _searchText = string.Empty;
        public string SearchText
        {
            get => _searchText;
            set
            {
                _searchText = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)SearchCommand).RaiseCanExecuteChanged();
            }
        }

        private bool _isSearching;
        public bool IsSearching
        {
            get => _isSearching;
            set
            {
                _isSearching = value;
                OnPropertyChanged();
                ((AsyncRelayCommand)SearchCommand).RaiseCanExecuteChanged();
                ((RelayCommand)StopSearchCommand).RaiseCanExecuteChanged();
            }
        }

        public ObservableCollection<Models.SearchResult> SearchResults { get; } = new();

        private Models.SearchResult? _selectedSearchResult;
        public Models.SearchResult? SelectedSearchResult
        {
            get => _selectedSearchResult;
            set
            {
                _selectedSearchResult = value;
                OnPropertyChanged();
                if (value != null)
                {
                    NavigateToOffsetRequested?.Invoke(value.Offset);
                }
            }
        }

        private SearchType _searchType;
        public SearchType SearchType
        {
            get => _searchType;
            set { _searchType = value; OnPropertyChanged(); }
        }

        public IEnumerable<SearchType> SearchTypes => Enum.GetValues(typeof(SearchType)).Cast<SearchType>();

        public int SearchPatternLength { get; private set; } = 0;
        #endregion

        #region Inspector Properties
        private string _asciiValue = string.Empty;
        public string AsciiValue { get => _asciiValue; set => SetProperty(ref _asciiValue, value); }

        private string _utf8Value = string.Empty;
        public string Utf8Value { get => _utf8Value; set => SetProperty(ref _utf8Value, value); }

        private string _charValue = string.Empty;
        public string CharValue { get => _charValue; set => SetProperty(ref _charValue, value); }

        private sbyte _int8Value;
        public sbyte Int8Value { get => _int8Value; set => SetProperty(ref _int8Value, value); }

        private byte _uint8Value;
        public byte UInt8Value { get => _uint8Value; set => SetProperty(ref _uint8Value, value); }

        private short _int16Value;
        public short Int16Value { get => _int16Value; set => SetProperty(ref _int16Value, value); }

        private ushort _uint16Value;
        public ushort UInt16Value { get => _uint16Value; set => SetProperty(ref _uint16Value, value); }

        private int _int32Value;
        public int Int32Value { get => _int32Value; set => SetProperty(ref _int32Value, value); }

        private uint _uint32Value;
        public uint UInt32Value { get => _uint32Value; set => SetProperty(ref _uint32Value, value); }

        private long _int64Value;
        public long Int64Value { get => _int64Value; set => SetProperty(ref _int64Value, value); }

        private ulong _uint64Value;
        public ulong UInt64Value { get => _uint64Value; set => SetProperty(ref _uint64Value, value); }

        private float _floatValue;
        public float FloatValue { get => _floatValue; set => SetProperty(ref _floatValue, value); }

        private double _doubleValue;
        public double DoubleValue { get => _doubleValue; set => SetProperty(ref _doubleValue, value); }
        #endregion

        public ICommand LoadFirstFileCommand { get; }
        public ICommand LoadSecondFileCommand { get; }
        public ICommand ExportSelectionCommand { get; }
        public ICommand ToggleInspectorCommand { get; }
        public ICommand CopySelectionCommand { get; }
        public ICommand CopyAsHexCommand { get; }
        public ICommand CopyAsAsciiCommand { get; }
        public ICommand SelectAllCommand { get; }
        public ICommand ClearSelectionCommand { get; }
        public ICommand ExportToFileCommand { get; }
        public ICommand CopyAsCArrayCommand { get; }
        public ICommand CopyAsBase64Command { get; }
        public ICommand SearchCommand { get; }
        public ICommand StopSearchCommand { get; }
        public ICommand ClearSearchCommand { get; }
        public ICommand NavigateToNextResultCommand { get; }
        public ICommand NavigateToPreviousResultCommand { get; }

        public event Action<long>? NavigateToOffsetRequested;

        public HexViewerViewModel(IDialogService dialogService)
        {
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _hexViewerService = new HexViewerService();
            _cancellationTokenSource = new CancellationTokenSource();

            LoadFirstFileCommand = new AsyncRelayCommand(async _ => await LoadFileAsync(1, null), _ => !IsLoading);
            LoadSecondFileCommand = new AsyncRelayCommand(async _ => await LoadFileAsync(2, null), _ => !IsLoading && IsSideBySideMode);
            ExportSelectionCommand = new AsyncRelayCommand(ExportSelectionAsync, _ => !IsLoading && SelectionLength > 0);
            ToggleInspectorCommand = new RelayCommand(_ => IsInspectorVisible = !IsInspectorVisible);

            CopySelectionCommand = new AsyncRelayCommand(CopySelectionAsync, _ => SelectionLength > 0);
            CopyAsHexCommand = new AsyncRelayCommand(CopyAsHexAsync, _ => SelectionLength > 0);
            CopyAsAsciiCommand = new AsyncRelayCommand(CopyAsAsciiAsync, _ => SelectionLength > 0);

            SelectAllCommand = new RelayCommand(SelectAll, _ => HexRows1 != null && HexRows1.Count > 0);
            ClearSelectionCommand = new RelayCommand(ClearSelection, _ => SelectionLength > 0);

            ExportToFileCommand = new AsyncRelayCommand(ExportToFileAsync, _ => SelectionLength > 0);
            CopyAsCArrayCommand = new AsyncRelayCommand(CopyAsCArrayAsync, _ => SelectionLength > 0);
            CopyAsBase64Command = new AsyncRelayCommand(CopyAsBase64Async, _ => SelectionLength > 0);

            SearchCommand = new AsyncRelayCommand(SearchAsync, _ => false); // Search is disabled for now
            StopSearchCommand = new RelayCommand(StopSearch, _ => IsSearching);
            ClearSearchCommand = new RelayCommand(ClearSearch);
            NavigateToNextResultCommand = new RelayCommand(NavigateToNextResult, _ => SearchResults.Count > 0);
            NavigateToPreviousResultCommand = new RelayCommand(NavigateToPreviousResult, _ => SearchResults.Count > 0);
        }

        public async Task LoadFileAsync(int gridNumber, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                filePath = await _dialogService.ShowOpenFileDialogAsync("Select File to View", "*", "All Files").ConfigureAwait(false);
            }

            if (filePath == null) return;

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                IsLoading = true;
                StatusText = $"Analyzing file {gridNumber}...";
            });

            try
            {
                if (gridNumber == 1)
                {
                    if (HexRows1 is IDisposable disposable1)
                        disposable1.Dispose();
                    HexRows1 = null;
                    File1Path = string.Empty;
                    File1Info = string.Empty;
                    OnPropertyChanged(nameof(HexRows1));
                }
                else
                {
                    if (HexRows2 is IDisposable disposable2)
                        disposable2.Dispose();
                    HexRows2 = null;
                    File2Path = string.Empty;
                    File2Info = string.Empty;
                    OnPropertyChanged(nameof(HexRows2));
                }

                var fileInfo = await _hexViewerService.GetFileInfoAsync(filePath, _cancellationTokenSource.Token);

                if (gridNumber == 1)
                {
                    var reader = S7.Services.VirtualFileReaderFactory.Create(filePath);
                    HexRows1 = new VirtualizingHexList(reader);
                    File1Path = filePath;
                    File1Info = FormatFileInfo(fileInfo);
                    OnPropertyChanged(nameof(HexRows1));
                }
                else
                {
                    var reader = S7.Services.VirtualFileReaderFactory.Create(filePath);
                    HexRows2 = new VirtualizingHexList(reader);
                    File2Path = filePath;
                    File2Info = FormatFileInfo(fileInfo);
                    OnPropertyChanged(nameof(HexRows2));
                }

                StatusText = $"✅ Loaded {fileInfo.FileName} ({fileInfo.FormattedSize})";
            }
            catch (OperationCanceledException)
            {
                StatusText = "❌ Loading cancelled";
            }
            catch (Exception ex)
            {
                StatusText = $"❌ Error loading file: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        private async Task ExportSelectionAsync(object? _ = null)
        {
            await _dialogService.ShowMessageAsync("Export", "Export functionality not yet implemented").ConfigureAwait(false);
        }

        private async Task UpdateInspectorPanelAsync()
        {
            if (string.IsNullOrEmpty(File1Path) || SelectedOffset < 0)
            {
                ClearInspectorPanel();
                return;
            }

            try
            {
                long analyzeOffset = SelectedOffset;
                int analyzeLength = 16;

                if (SelectionLength > 0)
                {
                    analyzeOffset = Math.Min(SelectionStartOffset, SelectionEndOffset);
                    analyzeLength = (int)SelectionLength;
                }

                if (HexRows1 is VirtualizingHexList virtualizingHexList)
                {
                    var analysis = await _hexViewerService.AnalyzeDataAsync(virtualizingHexList, analyzeOffset, analyzeLength, IsLittleEndian, _cancellationTokenSource.Token).ConfigureAwait(false);
                    UpdateInspectorValues(analysis, analyzeLength);
                }
            }
            catch (Exception ex)
            {
                StatusText = $"❌ Inspector error: {ex.Message}";
            }
        }

        private void UpdateInspectorValues(Dictionary<string, object> analysis, int dataLength)
        {
            AsciiValue = analysis.GetValueOrDefault("ASCII", string.Empty).ToString() ?? string.Empty;
            Utf8Value = analysis.GetValueOrDefault("UTF8", string.Empty).ToString() ?? string.Empty;

            if (dataLength >= 1)
            {
                CharValue = analysis.GetValueOrDefault("Char", string.Empty).ToString() ?? string.Empty;
                Int8Value = (sbyte)analysis.GetValueOrDefault("Int8", (sbyte)0);
                UInt8Value = (byte)analysis.GetValueOrDefault("UInt8", (byte)0);
            }
            else
            {
                CharValue = string.Empty;
                Int8Value = 0;
                UInt8Value = 0;
            }

            if (dataLength >= 2)
            {
                Int16Value = (short)analysis.GetValueOrDefault("Int16", (short)0);
                UInt16Value = (ushort)analysis.GetValueOrDefault("UInt16", (ushort)0);
            }
            else
            {
                Int16Value = 0;
                UInt16Value = 0;
            }

            if (dataLength >= 4)
            {
                Int32Value = (int)analysis.GetValueOrDefault("Int32", 0);
                UInt32Value = (uint)analysis.GetValueOrDefault("UInt32", 0u);
                FloatValue = (float)analysis.GetValueOrDefault("Float", 0.0f);
            }
            else
            {
                Int32Value = 0;
                UInt32Value = 0;
                FloatValue = 0.0f;
            }

            if (dataLength >= 8)
            {
                Int64Value = (long)analysis.GetValueOrDefault("Int64", 0L);
                UInt64Value = (ulong)analysis.GetValueOrDefault("UInt64", 0UL);
                DoubleValue = (double)analysis.GetValueOrDefault("Double", 0.0);
            }
            else
            {
                Int64Value = 0;
                UInt64Value = 0;
                DoubleValue = 0.0;
            }
        }

        private void ClearInspectorPanel()
        {
            AsciiValue = string.Empty;
            Utf8Value = string.Empty;
            CharValue = string.Empty;
            Int8Value = 0;
            UInt8Value = 0;
            Int16Value = 0;
            UInt16Value = 0;
            Int32Value = 0;
            UInt32Value = 0;
            Int64Value = 0;
            UInt64Value = 0;
            FloatValue = 0.0f;
            DoubleValue = 0.0;
        }

        private static string FormatFileInfo(HexViewerService.HexFileInfo fileInfo)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"📁 File: {fileInfo.FileName}");
            sb.AppendLine($"📏 Size: {fileInfo.FormattedSize} ({fileInfo.FileSize:N0} bytes)");
            sb.AppendLine($"🔒 MD5: {fileInfo.MD5Hash.ToUpperInvariant()}");
            sb.AppendLine($"📅 Modified: {fileInfo.LastModified:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"🏷️ Type: {fileInfo.FileType}");
            return sb.ToString();
        }

        #region Range Selection Methods

        private void SelectAll(object? _ = null)
        {
            if (HexRows1 is not VirtualizingHexList virtualizingHexList || virtualizingHexList.FileSize == 0) return;

            SelectionStartOffset = 0;
            SelectionEndOffset = virtualizingHexList.FileSize - 1;
            SelectedOffset = 0;
        }

        private void ClearSelection(object? _ = null)
        {
            SelectionStartOffset = -1;
            SelectionEndOffset = -1;
            SelectedOffset = -1;
        }

        #endregion

        #region Copy Methods

        private async Task CopySelectionAsync(object? _ = null)
        {
            await CopyAsHexAsync();
        }

        private async Task CopyAsHexAsync(object? _ = null)
        {
            if (SelectionLength == 0 || HexRows1 is not VirtualizingHexList list)
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                var buffer = list.ReadRange(start, length);
                var hexString = Convert.ToHexString(buffer);
                var formattedHex = string.Join(" ", Enumerable.Range(0, buffer.Length)
                    .Select(i => hexString.Substring(i * 2, 2)));

                await SetClipboardTextAsync(formattedHex);
                StatusText = $"✅ Copied {buffer.Length} bytes as hex to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        private async Task CopyAsAsciiAsync(object? _ = null)
        {
            if (SelectionLength == 0 || HexRows1 is not VirtualizingHexList list)
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                var buffer = list.ReadRange(start, length);
                var asciiString = new StringBuilder();
                for (int i = 0; i < buffer.Length; i++)
                {
                    var b = buffer[i];
                    asciiString.Append(char.IsControl((char)b) ? '.' : (char)b);
                }

                await SetClipboardTextAsync(asciiString.ToString());
                StatusText = $"✅ Copied {buffer.Length} bytes as ASCII to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        private async Task SetClipboardTextAsync(string text)
        {
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
                {
                    var clipboard = desktop.MainWindow?.Clipboard;
                    if (clipboard != null)
                    {
                        await clipboard.SetTextAsync(text);
                    }
                }
            });
        }

        #endregion

        #region Enhanced Export and Copy Methods

        private async Task ExportToFileAsync(object? _ = null)
        {
            if (SelectionLength == 0 || HexRows1 is not VirtualizingHexList list)
            {
                await _dialogService.ShowMessageAsync("Export", "No selection to export").ConfigureAwait(false);
                return;
            }

            try
            {
                var fileName = $"selection_0x{Math.Min(SelectionStartOffset, SelectionEndOffset):X8}_{SelectionLength}bytes.bin";
                var filePath = await _dialogService.ShowSaveFileDialogAsync("Export Selection", "bin", "Binary Files").ConfigureAwait(false);

                if (string.IsNullOrEmpty(filePath)) return;

                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                var buffer = list.ReadRange(start, length);
                await File.WriteAllBytesAsync(filePath, buffer, _cancellationTokenSource.Token);
                StatusText = $"✅ Exported {length} bytes to {Path.GetFileName(filePath)}";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Export Error", $"Failed to export selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        private async Task CopyAsCArrayAsync(object? _ = null)
        {
            if (SelectionLength == 0 || HexRows1 is not VirtualizingHexList list)
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                var buffer = list.ReadRange(start, length);
                var sb = new StringBuilder();
                sb.AppendLine($"// Selection from offset 0x{start:X8}, {length} bytes");
                sb.AppendLine($"unsigned char data[{length}] = {{");

                for (int i = 0; i < length; i++)
                {
                    if (i % 16 == 0)
                    {
                        if (i > 0) sb.AppendLine();
                        sb.Append("    ");
                    }

                    sb.Append($"0x{buffer[i]:X2}");
                    if (i < length - 1) sb.Append(", ");
                }

                sb.AppendLine();
                sb.AppendLine("};");

                await SetClipboardTextAsync(sb.ToString());
                StatusText = $"✅ Copied {length} bytes as C array to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        private async Task CopyAsBase64Async(object? _ = null)
        {
            if (SelectionLength == 0 || HexRows1 is not VirtualizingHexList list)
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                var buffer = list.ReadRange(start, length);
                var base64String = Convert.ToBase64String(buffer);

                await SetClipboardTextAsync(base64String);
                StatusText = $"✅ Copied {length} bytes as Base64 to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        #endregion

        #region Search Methods
        private async Task SearchAsync(object? _ = null)
        {
            IsSearching = true;
            SearchResults.Clear();
            SearchPatternLength = 0;

            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            try
            {
                if (HexRows1 is not VirtualizingHexList listToSearch)
                {
                    StatusText = "❌ No file loaded to search.";
                    return;
                }

                StatusText = $"Searching for '{SearchText}'...";

                var progress = new Progress<long>(offset => SearchResults.Add(new SearchResult(1, offset)));
                await _hexViewerService.SearchAsync(listToSearch, SearchText, SearchType, progress, token);

                if (SearchResults.Any())
                {
                    byte[] pattern;
                    try
                    {
                        pattern = SearchType switch
                        {
                            SearchType.Hex => Convert.FromHexString(SearchText.Replace(" ", "").Replace("0x", "")),
                            SearchType.SHA1 => Convert.FromHexString(SearchText.Replace(" ", "").Replace("0x", "")),
                            SearchType.Text => Encoding.UTF8.GetBytes(SearchText),
                            _ => Array.Empty<byte>()
                        };
                    }
                    catch { pattern = Array.Empty<byte>(); }
                    SearchPatternLength = pattern.Length;

                    StatusText = $"✅ Found {SearchResults.Count} occurrences.";
                    SelectedSearchResult = SearchResults.FirstOrDefault();
                }
                else
                {
                    StatusText = $"ℹ️ No occurrences found for '{SearchText}'.";
                }
            }
            catch (OperationCanceledException)
            {
                StatusText = "❌ Search cancelled.";
            }
            catch (Exception ex)
            {
                StatusText = $"❌ Search error: {ex.Message}";
            }
            finally
            {
                IsSearching = false;
                OnPropertyChanged(nameof(SearchResults)); // To refresh the view
                ((RelayCommand)NavigateToNextResultCommand).RaiseCanExecuteChanged();
                ((RelayCommand)NavigateToPreviousResultCommand).RaiseCanExecuteChanged();
            }
        }

        private void StopSearch(object? _ = null)
        {
            _cancellationTokenSource?.Cancel();
        }

        private void ClearSearch(object? _ = null)
        {
            SearchResults.Clear();
            SearchPatternLength = 0;
            OnPropertyChanged(nameof(SearchResults));
            StatusText = "Ready";
        }

        private void NavigateToNextResult(object? _ = null)
        {
            if (SearchResults.Count == 0) return;

            if (SelectedSearchResult == null)
            {
                SelectedSearchResult = SearchResults[0];
                return;
            }

            var currentIndex = SearchResults.IndexOf(SelectedSearchResult);
            if (currentIndex < SearchResults.Count - 1)
            {
                SelectedSearchResult = SearchResults[currentIndex + 1];
            }
            else
            {
                SelectedSearchResult = SearchResults[0];
            }
        }

        private void NavigateToPreviousResult(object? _ = null)
        {
            if (SearchResults.Count == 0) return;

            if (SelectedSearchResult == null)
            {
                SelectedSearchResult = SearchResults[^1];
                return;
            }

            var currentIndex = SearchResults.IndexOf(SelectedSearchResult);
            if (currentIndex > 0)
            {
                SelectedSearchResult = SearchResults[currentIndex - 1];
            }
            else
            {
                SelectedSearchResult = SearchResults[^1];
            }
        }
        #endregion

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
            if (HexRows1 is IDisposable disposable1)
                disposable1.Dispose();
            if (HexRows2 is IDisposable disposable2)
                disposable2.Dispose();
        }
    }
}
