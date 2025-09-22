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
using Avalonia.Threading;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using Avalonia;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// ViewModel for optimized hex viewing with chunked loading, side-by-side comparison, and data analysis.
    /// Supports large files without blocking the UI thread.
    /// </summary>
    public sealed class HexViewerViewModel : ViewModelBase, IDisposable
    {
        private readonly HexViewerService _hexViewerService;
        private readonly IDialogService _dialogService;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private const int MaxDisplayRows = 10000; // Limit for performance

        // Selection state tracking
        private bool _isSelecting = false;
        private long _selectionAnchor = -1;
        private bool _shiftKeyPressed = false;
        private bool _ctrlKeyPressed = false;
        private readonly HashSet<long> _multiSelection = new();

        #region Properties

        /// <summary>
        /// Gets the hex rows for the first file.
        /// </summary>
        public ObservableCollection<HexViewerService.HexRow> HexRows1 { get; } = new();

        /// <summary>
        /// Gets the hex rows for the second file (side-by-side mode).
        /// </summary>
        public ObservableCollection<HexViewerService.HexRow> HexRows2 { get; } = new();

        private string _file1Path = string.Empty;
        /// <summary>
        /// Gets or sets the path to the first file.
        /// </summary>
        public string File1Path
        {
            get => _file1Path;
            set { _file1Path = value; OnPropertyChanged(); }
        }

        private string _file2Path = string.Empty;
        /// <summary>
        /// Gets or sets the path to the second file.
        /// </summary>
        public string File2Path
        {
            get => _file2Path;
            set { _file2Path = value; OnPropertyChanged(); }
        }

        private string _file1Info = string.Empty;
        /// <summary>
        /// Gets or sets the information about the first file.
        /// </summary>
        public string File1Info
        {
            get => _file1Info;
            set { _file1Info = value; OnPropertyChanged(); }
        }

        private string _file2Info = string.Empty;
        /// <summary>
        /// Gets or sets the information about the second file.
        /// </summary>
        public string File2Info
        {
            get => _file2Info;
            set { _file2Info = value; OnPropertyChanged(); }
        }

        private bool _isSideBySideMode;
        /// <summary>
        /// Gets or sets a value indicating whether side-by-side mode is enabled.
        /// </summary>
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

        /// <summary>
        /// Gets a value indicating whether the second panel should be shown.
        /// </summary>
        public bool ShowSecondPanel => IsSideBySideMode;

        private GridLength _secondPanelWidth = new GridLength(0, GridUnitType.Pixel);
        /// <summary>
        /// Gets or sets the width of the second panel.
        /// </summary>
        public GridLength SecondPanelWidth
        {
            get => _secondPanelWidth;
            set { _secondPanelWidth = value; OnPropertyChanged(); }
        }

        // Width of the Inspector panel (right column). When collapsed, set to 0.
        private GridLength _inspectorWidth = new GridLength(350, GridUnitType.Pixel);
        public GridLength InspectorWidth
        {
            get => _inspectorWidth;
            set { _inspectorWidth = value; OnPropertyChanged(); }
        }

        // Separator width between viewers. Set to 0 when not side-by-side.
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
        /// <summary>
        /// Gets or sets a value indicating whether files are currently being loaded.
        /// </summary>
        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        private double _loadingProgress;
        /// <summary>
        /// Gets or sets the loading progress percentage.
        /// </summary>
        public double LoadingProgress
        {
            get => _loadingProgress;
            set { _loadingProgress = value; OnPropertyChanged(); }
        }

        private string _statusText = "Ready";
        /// <summary>
        /// Gets or sets the status text.
        /// </summary>
        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        private string _searchText = string.Empty;
        /// <summary>
        /// Gets or sets the search text.
        /// </summary>
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

        private bool _isLittleEndian = true;
        /// <summary>
        /// Gets or sets a value indicating whether multi-byte values should be interpreted as little-endian.
        /// </summary>
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
        /// <summary>
        /// Gets or sets a value indicating whether view synchronization is enabled.
        /// </summary>
        public bool IsSynchronizationEnabled
        {
            get => _isSynchronizationEnabled;
            set { _isSynchronizationEnabled = value; OnPropertyChanged(); }
        }

        private long _selectedOffset;
        /// <summary>
        /// Gets or sets the selected byte offset.
        /// </summary>
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
        /// <summary>
        /// Gets or sets the start offset of the selection range.
        /// </summary>
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
        /// <summary>
        /// Gets or sets the end offset of the selection range.
        /// </summary>
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

        /// <summary>
        /// Gets the length of the current selection.
        /// </summary>
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

        /// <summary>
        /// Checks if the given offset is within the current selection range.
        /// </summary>
        public bool IsOffsetInSelection(long offset)
        {
            if (SelectionStartOffset < 0 || SelectionEndOffset < 0) return false;
            var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
            var end = Math.Max(SelectionStartOffset, SelectionEndOffset);
            return offset >= start && offset <= end;
        }

        private List<long> _searchResults = new();
        /// <summary>
        /// Gets or sets the list of search result offsets.
        /// </summary>
        public List<long> SearchResults
        {
            get => _searchResults;
            set
            {
                _searchResults = value;
                OnPropertyChanged();
            }
        }

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

        #endregion

        #region Commands

        /// <summary>
        /// Gets the command to load the first file.
        /// </summary>
        public ICommand LoadFirstFileCommand { get; }

        /// <summary>
        /// Gets the command to load the second file.
        /// </summary>
        public ICommand LoadSecondFileCommand { get; }

        /// <summary>
        /// Gets the command to export the selection.
        /// </summary>
        public ICommand ExportSelectionCommand { get; }

        /// <summary>
        /// Gets the command to search for hex patterns.
        /// </summary>
        public ICommand SearchCommand { get; }

        /// <summary>
        /// Gets the command to refresh the current view.
        /// </summary>
        public ICommand RefreshCommand { get; }

        /// <summary>
        /// Gets the command to go to a specific offset.
        /// </summary>
        public ICommand GoToOffsetCommand { get; }

        /// <summary>
        /// Toggles the visibility (width) of the Inspector panel.
        /// </summary>
        public ICommand ToggleInspectorCommand { get; }

        /// <summary>
        /// Sets the selected offset from hex cell clicks.
        /// </summary>
        public ICommand SetSelectedOffsetCommand { get; }

        /// <summary>
        /// Handles hex cell mouse down events for range selection.
        /// </summary>
        public ICommand HexCellMouseDownCommand { get; }

        /// <summary>
        /// Handles hex cell mouse enter events for drag selection.
        /// </summary>
        public ICommand HexCellMouseEnterCommand { get; }

        /// <summary>
        /// Handles hex cell mouse up events to end selection.
        /// </summary>
        public ICommand HexCellMouseUpCommand { get; }

        /// <summary>
        /// Copies the selected bytes to clipboard.
        /// </summary>
        public ICommand CopySelectionCommand { get; }

        /// <summary>
        /// Copies the selected bytes as hex string to clipboard.
        /// </summary>
        public ICommand CopyAsHexCommand { get; }

        /// <summary>
        /// Copies the selected bytes as ASCII string to clipboard.
        /// </summary>
        public ICommand CopyAsAsciiCommand { get; }

        /// <summary>
        /// Selects all bytes in the current view.
        /// </summary>
        public ICommand SelectAllCommand { get; }

        /// <summary>
        /// Clears the current selection.
        /// </summary>
        public ICommand ClearSelectionCommand { get; }

        /// <summary>
        /// Exports selection to file with various formats.
        /// </summary>
        public ICommand ExportToFileCommand { get; }

        /// <summary>
        /// Copies selection as C array format.
        /// </summary>
        public ICommand CopyAsCArrayCommand { get; }

        /// <summary>
        /// Copies selection as Base64 string.
        /// </summary>
        public ICommand CopyAsBase64Command { get; }

        /// <summary>
        /// Updates keyboard modifier states.
        /// </summary>
        public ICommand UpdateKeyboardModifiersCommand { get; }

        
        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="HexViewerViewModel"/> class.
        /// </summary>
        /// <param name="dialogService">The dialog service.</param>
        public HexViewerViewModel(IDialogService dialogService)
        {
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _hexViewerService = new HexViewerService();
            _cancellationTokenSource = new CancellationTokenSource();

            LoadFirstFileCommand = new AsyncRelayCommand(_ => LoadFirstFileAsync(), _ => !IsLoading);
            LoadSecondFileCommand = new AsyncRelayCommand(_ => LoadSecondFileAsync(), _ => !IsLoading && IsSideBySideMode);
            ExportSelectionCommand = new AsyncRelayCommand(_ => ExportSelectionAsync(), _ => !IsLoading && SelectionLength > 0);
            SearchCommand = new AsyncRelayCommand(_ => SearchAsync(), _ => !IsLoading && !string.IsNullOrWhiteSpace(SearchText));
            RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), _ => !IsLoading);
            GoToOffsetCommand = new AsyncRelayCommand(_ => GoToOffsetAsync(), _ => !IsLoading);
            ToggleInspectorCommand = new RelayCommand(_ => IsInspectorVisible = !IsInspectorVisible);
            SetSelectedOffsetCommand = new RelayCommand(param => HandleCellClick(param));
            
            // Range selection commands
            HexCellMouseDownCommand = new RelayCommand(param => HandleMouseDown(param));
            HexCellMouseEnterCommand = new RelayCommand(param => HandleMouseEnter(param));
            HexCellMouseUpCommand = new RelayCommand(param => HandleMouseUp(param));
            
            // Copy commands
            CopySelectionCommand = new AsyncRelayCommand(_ => CopySelectionAsync(), _ => SelectionLength > 0);
            CopyAsHexCommand = new AsyncRelayCommand(_ => CopyAsHexAsync(), _ => SelectionLength > 0);
            CopyAsAsciiCommand = new AsyncRelayCommand(_ => CopyAsAsciiAsync(), _ => SelectionLength > 0);
            
            // Selection commands
            SelectAllCommand = new RelayCommand(_ => SelectAll(), _ => HexRows1.Count > 0);
            ClearSelectionCommand = new RelayCommand(_ => ClearSelection(), _ => SelectionLength > 0);
            
            // Enhanced export and copy commands
            ExportToFileCommand = new AsyncRelayCommand(_ => ExportToFileAsync(), _ => SelectionLength > 0);
            CopyAsCArrayCommand = new AsyncRelayCommand(_ => CopyAsCArrayAsync(), _ => SelectionLength > 0);
            CopyAsBase64Command = new AsyncRelayCommand(_ => CopyAsBase64Async(), _ => SelectionLength > 0);
            UpdateKeyboardModifiersCommand = new RelayCommand(param => UpdateKeyboardModifiers(param));
        }

        /// <summary>
        /// Loads a file into the hex viewer.
        /// </summary>
        /// <param name="filePath">The path to the file to load.</param>
        /// <param name="gridNumber">The grid number (1 or 2).</param>
        public async Task LoadFileAsync(string filePath, int gridNumber = 1)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                return;
            }

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                IsLoading = true;
                LoadingProgress = 0;
                StatusText = $"Loading file {gridNumber}...";
            });

            try
            {
                var collection = gridNumber == 1 ? HexRows1 : HexRows2;
                await Dispatcher.UIThread.InvokeAsync(() => collection.Clear());

                // Load file information
                var progress = new Progress<long>(bytes =>
                {
                    Dispatcher.UIThread.Post(() => LoadingProgress = Math.Min(50, (bytes / 1024.0 / 1024.0) * 10));
                });

                var fileInfo = await _hexViewerService.GetFileInfoAsync(filePath, _cancellationTokenSource.Token, progress);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (gridNumber == 1)
                    {
                        File1Path = filePath;
                        File1Info = FormatFileInfo(fileInfo);
                    }
                    else
                    {
                        File2Path = filePath;
                        File2Info = FormatFileInfo(fileInfo);
                    }
                    LoadingProgress = 60;
                });

                // Load hex data
                var rowProgress = new Progress<int>(rows =>
                {
                    Dispatcher.UIThread.Post(() => LoadingProgress = 60 + (rows / (double)MaxDisplayRows) * 40);
                });

                var hexRows = await _hexViewerService.LoadHexDataAsync(filePath, 0, MaxDisplayRows, _cancellationTokenSource.Token, rowProgress);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    collection.Clear();
                    foreach (var row in hexRows)
                    {
                        collection.Add(row);
                    }
                    LoadingProgress = 100;
                    StatusText = $"✅ Loaded {collection.Count} rows from {fileInfo.FileName} ({fileInfo.FormattedSize})";
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    StatusText = "❌ Loading cancelled";
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    StatusText = $"❌ Error loading file: {ex.Message}";
                });
            }
            finally
            {
                await Dispatcher.UIThread.InvokeAsync(() => IsLoading = false);
            }
        }

        /// <summary>
        /// Loads the first file.
        /// </summary>
        private async Task LoadFirstFileAsync()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select File to View", "*", "All Files").ConfigureAwait(false);
            if (filePath != null)
            {
                await LoadFileAsync(filePath, 1);
            }
        }

        /// <summary>
        /// Loads the second file for side-by-side comparison.
        /// </summary>
        private async Task LoadSecondFileAsync()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Second File", "*", "All Files").ConfigureAwait(false);
            if (filePath != null)
            {
                await LoadFileAsync(filePath, 2);
            }
        }

        /// <summary>
        /// Exports the current selection.
        /// </summary>
        private async Task ExportSelectionAsync()
        {
            // Implementation for exporting selection
            await _dialogService.ShowMessageAsync("Export", "Export functionality not yet implemented").ConfigureAwait(false);
        }

        /// <summary>
        /// Searches for hex patterns in the loaded files.
        /// </summary>
        private async Task SearchAsync()
        {
            if (string.IsNullOrWhiteSpace(SearchText) || string.IsNullOrEmpty(File1Path))
            {
                return;
            }

            try
            {
                IsLoading = true;
                StatusText = "Searching...";

                var progress = new Progress<long>(bytes =>
                {
                    Dispatcher.UIThread.Post(() => LoadingProgress = (bytes / 1024.0 / 1024.0) * 10);
                });

                var results = await _hexViewerService.SearchHexPatternAsync(File1Path, SearchText, 100, _cancellationTokenSource.Token, progress).ConfigureAwait(false);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    SearchResults = results;
                    if (results.Count > 0)
                    {
                        StatusText = $"✅ Found {results.Count} matches";
                        // Navigate to first match
                        SelectedOffset = results[0];
                    }
                    else
                    {
                        StatusText = "❌ Pattern not found";
                    }
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    StatusText = $"❌ Search error: {ex.Message}";
                });
            }
            finally
            {
                IsLoading = false;
            }
        }

        /// <summary>
        /// Refreshes the current view.
        /// </summary>
        private async Task RefreshAsync()
        {
            if (!string.IsNullOrEmpty(File1Path))
            {
                await LoadFileAsync(File1Path, 1);
            }
            if (!string.IsNullOrEmpty(File2Path) && IsSideBySideMode)
            {
                await LoadFileAsync(File2Path, 2);
            }
        }

        /// <summary>
        /// Goes to a specific offset.
        /// </summary>
        private async Task GoToOffsetAsync()
        {
            // Implementation for going to specific offset
            await _dialogService.ShowMessageAsync("Go To", "Go to offset functionality not yet implemented").ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the inspector panel with data analysis based on current selection.
        /// </summary>
        private async Task UpdateInspectorPanelAsync()
        {
            if (string.IsNullOrEmpty(File1Path) || SelectedOffset < 0)
            {
                ClearInspectorPanel();
                return;
            }

            try
            {
                // Determine the offset and length to analyze
                long analyzeOffset = SelectedOffset;
                int analyzeLength = 16; // Default to 16 bytes for analysis
                
                // If we have a selection, use the selection for analysis
                if (SelectionLength > 0)
                {
                    analyzeOffset = Math.Min(SelectionStartOffset, SelectionEndOffset);
                    analyzeLength = Math.Min((int)SelectionLength, 16); // Limit to 16 bytes for performance
                }

                var analysis = await _hexViewerService.AnalyzeDataAsync(File1Path, analyzeOffset, analyzeLength, IsLittleEndian, _cancellationTokenSource.Token).ConfigureAwait(false);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    UpdateInspectorValues(analysis, analyzeLength);
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    StatusText = $"❌ Inspector error: {ex.Message}";
                });
            }
        }

        /// <summary>
        /// Updates inspector values based on analysis results and selection length.
        /// </summary>
        private void UpdateInspectorValues(Dictionary<string, object> analysis, int dataLength)
        {
            // String values - always show for any selection
            AsciiValue = analysis.GetValueOrDefault("ASCII", string.Empty).ToString() ?? string.Empty;
            Utf8Value = analysis.GetValueOrDefault("UTF8", string.Empty).ToString() ?? string.Empty;
            
            // Single byte values - always available
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

            // 2-byte values (word) - available when selection is 2+ bytes
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

            // 4-byte values (dword) - available when selection is 4+ bytes
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

            // 8-byte values (qword) - available when selection is 8+ bytes
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

        /// <summary>
        /// Clears the inspector panel.
        /// </summary>
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

        /// <summary>
        /// Formats file information for display.
        /// </summary>
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

        /// <summary>
        /// Handles cell click events with keyboard modifier support.
        /// </summary>
        private void HandleCellClick(object? parameter)
        {
            if (parameter is not long offset || offset < 0) return;

            // TODO: In a real implementation, you would detect keyboard modifiers here
            // For now, we'll simulate the behavior
            var shiftPressed = _shiftKeyPressed;
            var ctrlPressed = _ctrlKeyPressed;

            if (shiftPressed && _selectionAnchor >= 0)
            {
                // Shift+Click: Extend selection from anchor to current offset
                SelectionStartOffset = _selectionAnchor;
                SelectionEndOffset = offset;
                SelectedOffset = offset;
            }
            else if (ctrlPressed)
            {
                // Ctrl+Click: Toggle selection (for future multi-selection support)
                // For now, just treat as normal click
                StartNewSelection(offset);
            }
            else
            {
                // Normal click: Start new selection
                StartNewSelection(offset);
            }

            UpdateStatusText();
        }

        /// <summary>
        /// Handles mouse down events for drag selection.
        /// </summary>
        private void HandleMouseDown(object? parameter)
        {
            if (parameter is not long offset || offset < 0) return;

            _isSelecting = true;
            _selectionAnchor = offset;
            StartNewSelection(offset);
        }

        /// <summary>
        /// Handles mouse enter events during drag selection.
        /// </summary>
        private void HandleMouseEnter(object? parameter)
        {
            if (!_isSelecting || parameter is not long offset || offset < 0) return;

            // Update selection range during drag
            SelectionStartOffset = _selectionAnchor;
            SelectionEndOffset = offset;
            SelectedOffset = offset;
            UpdateStatusText();
        }

        /// <summary>
        /// Handles mouse up events to end drag selection.
        /// </summary>
        private void HandleMouseUp(object? parameter)
        {
            _isSelecting = false;
        }

        /// <summary>
        /// Starts a new selection at the specified offset.
        /// </summary>
        private void StartNewSelection(long offset)
        {
            _selectionAnchor = offset;
            SelectionStartOffset = offset;
            SelectionEndOffset = offset;
            SelectedOffset = offset;
        }

        /// <summary>
        /// Selects all bytes in the current view.
        /// </summary>
        private void SelectAll()
        {
            if (HexRows1.Count == 0) return;

            var firstRow = HexRows1.First();
            var lastRow = HexRows1.Last();

            // Find first and last valid offsets
            var firstOffset = firstRow.Offsets.FirstOrDefault(o => o >= 0);
            var lastOffset = lastRow.Offsets.LastOrDefault(o => o >= 0);

            if (firstOffset >= 0 && lastOffset >= 0)
            {
                SelectionStartOffset = firstOffset;
                SelectionEndOffset = lastOffset;
                SelectedOffset = firstOffset;
                _selectionAnchor = firstOffset;
                UpdateStatusText();
            }
        }

        /// <summary>
        /// Clears the current selection.
        /// </summary>
        private void ClearSelection()
        {
            SelectionStartOffset = -1;
            SelectionEndOffset = -1;
            _selectionAnchor = -1;
            UpdateStatusText();
        }

        /// <summary>
        /// Updates the status text with selection information.
        /// </summary>
        private void UpdateStatusText()
        {
            if (SelectionLength > 0)
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var end = Math.Max(SelectionStartOffset, SelectionEndOffset);
                StatusText = $"Selected {SelectionLength} bytes (0x{start:X8} - 0x{end:X8})";
            }
            else if (SelectedOffset >= 0)
            {
                StatusText = $"Selected offset: 0x{SelectedOffset:X8}";
            }
            else
            {
                StatusText = "Ready";
            }
        }

        #endregion

        #region Copy Methods

        /// <summary>
        /// Copies the selected bytes to clipboard in hex format.
        /// </summary>
        private async Task CopySelectionAsync()
        {
            await CopyAsHexAsync();
        }

        /// <summary>
        /// Copies the selected bytes as hex string to clipboard.
        /// </summary>
        private async Task CopyAsHexAsync()
        {
            if (SelectionLength == 0 || string.IsNullOrEmpty(File1Path))
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                using var stream = new FileStream(File1Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                stream.Seek(start, SeekOrigin.Begin);

                var buffer = new byte[length];
                var bytesRead = await stream.ReadAsync(buffer, 0, length, _cancellationTokenSource.Token);

                var hexString = Convert.ToHexString(buffer, 0, bytesRead);
                
                // Format as space-separated hex bytes
                var formattedHex = string.Join(" ", Enumerable.Range(0, bytesRead)
                    .Select(i => hexString.Substring(i * 2, 2)));

                await SetClipboardTextAsync(formattedHex);
                StatusText = $"✅ Copied {bytesRead} bytes as hex to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Copies the selected bytes as ASCII string to clipboard.
        /// </summary>
        private async Task CopyAsAsciiAsync()
        {
            if (SelectionLength == 0 || string.IsNullOrEmpty(File1Path))
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                using var stream = new FileStream(File1Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                stream.Seek(start, SeekOrigin.Begin);

                var buffer = new byte[length];
                var bytesRead = await stream.ReadAsync(buffer, 0, length, _cancellationTokenSource.Token);

                // Convert to ASCII, replacing non-printable characters with '.'
                var asciiString = new StringBuilder();
                for (int i = 0; i < bytesRead; i++)
                {
                    var b = buffer[i];
                    asciiString.Append(char.IsControl((char)b) ? '.' : (char)b);
                }

                await SetClipboardTextAsync(asciiString.ToString());
                StatusText = $"✅ Copied {bytesRead} bytes as ASCII to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Sets text to the system clipboard.
        /// </summary>
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

        /// <summary>
        /// Exports the selected bytes to a file with various format options.
        /// </summary>
        private async Task ExportToFileAsync()
        {
            if (SelectionLength == 0 || string.IsNullOrEmpty(File1Path))
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

                using var sourceStream = new FileStream(File1Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var targetStream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
                
                sourceStream.Seek(start, SeekOrigin.Begin);
                
                var buffer = new byte[Math.Min(8192, length)]; // Use 8KB buffer
                var totalBytesRead = 0;
                
                while (totalBytesRead < length)
                {
                    var bytesToRead = Math.Min(buffer.Length, length - totalBytesRead);
                    var bytesRead = await sourceStream.ReadAsync(buffer, 0, bytesToRead, _cancellationTokenSource.Token);
                    
                    if (bytesRead == 0) break;
                    
                    await targetStream.WriteAsync(buffer, 0, bytesRead, _cancellationTokenSource.Token);
                    totalBytesRead += bytesRead;
                }

                StatusText = $"✅ Exported {totalBytesRead} bytes to {Path.GetFileName(filePath)}";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Export Error", $"Failed to export selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Copies the selected bytes as C array format to clipboard.
        /// </summary>
        private async Task CopyAsCArrayAsync()
        {
            if (SelectionLength == 0 || string.IsNullOrEmpty(File1Path))
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                using var stream = new FileStream(File1Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                stream.Seek(start, SeekOrigin.Begin);

                var buffer = new byte[length];
                var bytesRead = await stream.ReadAsync(buffer, 0, length, _cancellationTokenSource.Token);

                var sb = new StringBuilder();
                sb.AppendLine($"// Selection from offset 0x{start:X8}, {bytesRead} bytes");
                sb.AppendLine($"unsigned char data[{bytesRead}] = {{");
                
                for (int i = 0; i < bytesRead; i++)
                {
                    if (i % 16 == 0)
                    {
                        if (i > 0) sb.AppendLine();
                        sb.Append("    ");
                    }
                    
                    sb.Append($"0x{buffer[i]:X2}");
                    if (i < bytesRead - 1) sb.Append(", ");
                }
                
                sb.AppendLine();
                sb.AppendLine("};");

                await SetClipboardTextAsync(sb.ToString());
                StatusText = $"✅ Copied {bytesRead} bytes as C array to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Copies the selected bytes as Base64 string to clipboard.
        /// </summary>
        private async Task CopyAsBase64Async()
        {
            if (SelectionLength == 0 || string.IsNullOrEmpty(File1Path))
            {
                await _dialogService.ShowMessageAsync("Copy", "No selection to copy").ConfigureAwait(false);
                return;
            }

            try
            {
                var start = Math.Min(SelectionStartOffset, SelectionEndOffset);
                var length = (int)SelectionLength;

                using var stream = new FileStream(File1Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                stream.Seek(start, SeekOrigin.Begin);

                var buffer = new byte[length];
                var bytesRead = await stream.ReadAsync(buffer, 0, length, _cancellationTokenSource.Token);

                var base64String = Convert.ToBase64String(buffer, 0, bytesRead);
                
                await SetClipboardTextAsync(base64String);
                StatusText = $"✅ Copied {bytesRead} bytes as Base64 to clipboard";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Copy Error", $"Failed to copy selection: {ex.Message}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Updates keyboard modifier states from UI events.
        /// </summary>
        private void UpdateKeyboardModifiers(object? parameter)
        {
            if (parameter is string modifierState)
            {
                var parts = modifierState.Split(',');
                if (parts.Length >= 2)
                {
                    _shiftKeyPressed = bool.Parse(parts[0]);
                    _ctrlKeyPressed = bool.Parse(parts[1]);
                }
            }
        }

        #endregion

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
