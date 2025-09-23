#nullable enable
using System;
using System.Collections.Generic;
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

namespace S7_Csharp_Utility.ViewModels
{
    public sealed class HexViewerViewModel : ViewModelBase, IDisposable
    {
        private readonly HexViewerService _hexViewerService;
        private readonly IDialogService _dialogService;
        private readonly CancellationTokenSource _cancellationTokenSource;

        private bool _isSelecting = false;
        private long _selectionAnchor = -1;
        private bool _shiftKeyPressed = false;
        private bool _ctrlKeyPressed = false;
        private readonly HashSet<long> _multiSelection = new();

        public IList<HexViewerService.HexRow>? HexRows1 { get; private set; }
        public IList<HexViewerService.HexRow>? HexRows2 { get; private set; }

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
            set { _isLoading = value; OnPropertyChanged(); }
        }

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
        public ICommand RefreshCommand { get; }
        public ICommand ToggleInspectorCommand { get; }
        public ICommand SetSelectedOffsetCommand { get; }
        public ICommand HexCellMouseDownCommand { get; }
        public ICommand HexCellMouseEnterCommand { get; }
        public ICommand HexCellMouseUpCommand { get; }
        public ICommand CopySelectionCommand { get; }
        public ICommand CopyAsHexCommand { get; }
        public ICommand CopyAsAsciiCommand { get; }
        public ICommand SelectAllCommand { get; }
        public ICommand ClearSelectionCommand { get; }
        public ICommand ExportToFileCommand { get; }
        public ICommand CopyAsCArrayCommand { get; }
        public ICommand CopyAsBase64Command { get; }
        public ICommand UpdateKeyboardModifiersCommand { get; }
        
        public HexViewerViewModel(IDialogService dialogService)
        {
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            _hexViewerService = new HexViewerService();
            _cancellationTokenSource = new CancellationTokenSource();

            LoadFirstFileCommand = new AsyncRelayCommand(_ => LoadFirstFileAsync(), _ => !IsLoading);
            LoadSecondFileCommand = new AsyncRelayCommand(_ => LoadSecondFileAsync(), _ => !IsLoading && IsSideBySideMode);
            ExportSelectionCommand = new AsyncRelayCommand(_ => ExportSelectionAsync(), _ => !IsLoading && SelectionLength > 0);
            RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), _ => !IsLoading);
            ToggleInspectorCommand = new RelayCommand(_ => IsInspectorVisible = !IsInspectorVisible);
            SetSelectedOffsetCommand = new RelayCommand(param => HandleCellClick(param));
            
            HexCellMouseDownCommand = new RelayCommand(param => HandleMouseDown(param));
            HexCellMouseEnterCommand = new RelayCommand(param => HandleMouseEnter(param));
            HexCellMouseUpCommand = new RelayCommand(param => HandleMouseUp(param));
            
            CopySelectionCommand = new AsyncRelayCommand(_ => CopySelectionAsync(), _ => SelectionLength > 0);
            CopyAsHexCommand = new AsyncRelayCommand(_ => CopyAsHexAsync(), _ => SelectionLength > 0);
            CopyAsAsciiCommand = new AsyncRelayCommand(_ => CopyAsAsciiAsync(), _ => SelectionLength > 0);
            
            SelectAllCommand = new RelayCommand(_ => SelectAll(), _ => HexRows1 != null && HexRows1.Count > 0);
            ClearSelectionCommand = new RelayCommand(_ => ClearSelection(), _ => SelectionLength > 0);
            
            ExportToFileCommand = new AsyncRelayCommand(_ => ExportToFileAsync(), _ => SelectionLength > 0);
            CopyAsCArrayCommand = new AsyncRelayCommand(_ => CopyAsCArrayAsync(), _ => SelectionLength > 0);
            CopyAsBase64Command = new AsyncRelayCommand(_ => CopyAsBase64Async(), _ => SelectionLength > 0);
            UpdateKeyboardModifiersCommand = new RelayCommand(param => UpdateKeyboardModifiers(param));
        }

        public async Task LoadFileAsync(string filePath, int gridNumber = 1)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                return;
            }

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
                    HexRows1 = new VirtualizingHexList(filePath);
                    File1Path = filePath;
                    File1Info = FormatFileInfo(fileInfo);
                    OnPropertyChanged(nameof(HexRows1));
                }
                else
                {
                    HexRows2 = new VirtualizingHexList(filePath);
                    File2Path = filePath;
                    File2Info = FormatFileInfo(fileInfo);
                    OnPropertyChanged(nameof(HexRows2));
                }

                StatusText = $"✅ Loaded {fileInfo.FileName} ({fileInfo.FormattedSize})";
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

        private async Task LoadFirstFileAsync()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select File to View", "*", "All Files").ConfigureAwait(false);
            if (filePath != null)
            {
                await LoadFileAsync(filePath);
            }
        }

        private async Task LoadSecondFileAsync()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Second File", "*", "All Files").ConfigureAwait(false);
            if (filePath != null)
            {
                await LoadFileAsync(filePath, 2);
            }
        }

        private async Task ExportSelectionAsync()
        {
            await _dialogService.ShowMessageAsync("Export", "Export functionality not yet implemented").ConfigureAwait(false);
        }

        private async Task RefreshAsync()
        {
            if (!string.IsNullOrEmpty(File1Path))
            {
                await LoadFileAsync(File1Path);
            }
            if (!string.IsNullOrEmpty(File2Path) && IsSideBySideMode)
            {
                await LoadFileAsync(File2Path, 2);
            }
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

                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        UpdateInspectorValues(analysis, analyzeLength);
                    });
                }
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    StatusText = $"❌ Inspector error: {ex.Message}";
                });
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

        private void HandleCellClick(object? parameter)
        {
            if (parameter is not long offset || offset < 0) return;

            var shiftPressed = _shiftKeyPressed;
            var ctrlPressed = _ctrlKeyPressed;

            if (shiftPressed && _selectionAnchor >= 0)
            {
                SelectionStartOffset = _selectionAnchor;
                SelectionEndOffset = offset;
                SelectedOffset = offset;
            }
            else if (ctrlPressed)
            {
                StartNewSelection(offset);
            }
            else
            {
                StartNewSelection(offset);
            }

            UpdateStatusText();
        }

        private void HandleMouseDown(object? parameter)
        {
            if (parameter is not long offset || offset < 0) return;

            _isSelecting = true;
            _selectionAnchor = offset;
            StartNewSelection(offset);
        }

        private void HandleMouseEnter(object? parameter)
        {
            if (!_isSelecting || parameter is not long offset || offset < 0) return;

            SelectionStartOffset = _selectionAnchor;
            SelectionEndOffset = offset;
            SelectedOffset = offset;
            UpdateStatusText();
        }

        private void HandleMouseUp(object? parameter)
        {
            _isSelecting = false;
        }

        private void StartNewSelection(long offset)
        {
            _selectionAnchor = offset;
            SelectionStartOffset = offset;
            SelectionEndOffset = offset;
            SelectedOffset = offset;
        }

        private void SelectAll()
        {
            if (HexRows1 is not VirtualizingHexList virtualizingHexList || virtualizingHexList.FileSize == 0) return;

            SelectionStartOffset = 0;
            SelectionEndOffset = virtualizingHexList.FileSize - 1;
            SelectedOffset = 0;
            _selectionAnchor = 0;
            UpdateStatusText();
        }

        private void ClearSelection()
        {
            SelectionStartOffset = -1;
            SelectionEndOffset = -1;
            _selectionAnchor = -1;
            UpdateStatusText();
        }

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

        private async Task CopySelectionAsync()
        {
            await CopyAsHexAsync();
        }

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
                
                var buffer = new byte[Math.Min(8192, length)];
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
            if (HexRows1 is IDisposable disposable1)
                disposable1.Dispose();
            if (HexRows2 is IDisposable disposable2)
                disposable2.Dispose();
        }
    }
}
