using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Controls.Shapes;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility.Controls
{
    public partial class HexViewerControl : UserControl
    {
        private Canvas? _selectionCanvas;
        private ItemsControl? _hexRowsContainer;
        private ScrollViewer? _hexScrollViewer;
        
        private bool _isDragging;
        private Point _dragStartPoint;
        private long _selectionStartOffset = -1;
        private long _selectionEndOffset = -1;
        private readonly List<Rectangle> _selectionRectangles = new();
        
        private const double RowHeight = 20;
        private const double ByteWidth = 24;
        private const double OffsetWidth = 70;
        private const double SeparatorWidth = 8;
        
        private readonly double[] _hexColumnPositions = new double[16];

        public static readonly StyledProperty<IList<HexViewerService.HexRow>?> HexRowsProperty =
            AvaloniaProperty.Register<HexViewerControl, IList<HexViewerService.HexRow>?>(nameof(HexRows));

        public IList<HexViewerService.HexRow>? HexRows
        {
            get => GetValue(HexRowsProperty);
            set => SetValue(HexRowsProperty, value);
        }

        public HexViewerControl()
        {
            InitializeComponent();
            InitializeColumnPositions();
            
            Focusable = true;
            KeyDown += OnKeyDown;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            
            _selectionCanvas = this.FindControl<Canvas>("SelectionCanvas");
            _hexRowsContainer = this.FindControl<ItemsControl>("HexRowsContainer");
            _hexScrollViewer = this.FindControl<ScrollViewer>("HexScrollViewer");
        }

        private void InitializeColumnPositions()
        {
            double currentX = OffsetWidth;
            
            for (int i = 0; i < 8; i++)
            {
                _hexColumnPositions[i] = currentX;
                currentX += ByteWidth;
            }
            
            currentX += SeparatorWidth;
            
            for (int i = 8; i < 16; i++)
            {
                _hexColumnPositions[i] = currentX;
                currentX += ByteWidth;
            }
        }

        private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (_selectionCanvas == null) return;
            
            var position = e.GetPosition(_selectionCanvas);
            var offset = GetOffsetFromPosition(position);
            
            if (offset >= 0)
            {
                _isDragging = true;
                _dragStartPoint = position;
                _selectionStartOffset = offset;
                _selectionEndOffset = offset;
                
                var modifiers = e.KeyModifiers;
                
                if (modifiers.HasFlag(KeyModifiers.Shift) && DataContext is HexViewerViewModel viewModel && viewModel.SelectedOffset >= 0)
                {
                    _selectionStartOffset = viewModel.SelectedOffset;
                    _selectionEndOffset = offset;
                }
                else if (!modifiers.HasFlag(KeyModifiers.Control))
                {
                    _selectionStartOffset = offset;
                    _selectionEndOffset = offset;
                }
                
                UpdateSelection();
                e.Pointer.Capture(_selectionCanvas);
                e.Handled = true;
            }
        }

        private void OnPointerMoved(object? sender, PointerEventArgs e)
        {
            if (_isDragging)
            {
                var position = e.GetPosition(_selectionCanvas);
                var offset = GetOffsetFromPosition(position);
                
                if (offset >= 0)
                {
                    _selectionEndOffset = offset;
                    UpdateSelection();
                }
                e.Handled = true;
            }
        }

        private void OnPointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            if (_isDragging)
            {
                _isDragging = false;
                e.Pointer.Capture(null);
                
                if (DataContext is HexViewerViewModel viewModel)
                {
                    var start = Math.Min(_selectionStartOffset, _selectionEndOffset);
                    var end = Math.Max(_selectionStartOffset, _selectionEndOffset);
                    
                    viewModel.SelectionStartOffset = start;
                    viewModel.SelectionEndOffset = end;
                    viewModel.SelectedOffset = end;
                }
                
                e.Handled = true;
            }
        }

        private void OnKeyDown(object? sender, KeyEventArgs e)
        {
            if (DataContext is not HexViewerViewModel viewModel) return;

            var currentOffset = viewModel.SelectedOffset;
            var newOffset = currentOffset;
            var handled = true;

            switch (e.Key)
            {
                case Key.Left:
                    newOffset = Math.Max(0, currentOffset - 1);
                    break;
                case Key.Right:
                    newOffset = currentOffset + 1;
                    break;
                case Key.Up:
                    newOffset = Math.Max(0, currentOffset - 16);
                    break;
                case Key.Down:
                    newOffset = currentOffset + 16;
                    break;
                case Key.Home:
                    if (e.KeyModifiers.HasFlag(KeyModifiers.Control))
                        newOffset = 0;
                    else
                        newOffset = (currentOffset / 16) * 16;
                    break;
                case Key.End:
                    if (e.KeyModifiers.HasFlag(KeyModifiers.Control))
                    {
                        var lastRow = viewModel.HexRows1?.LastOrDefault();
                        if (lastRow != null)
                        {
                            newOffset = lastRow.Offsets.LastOrDefault(o => o >= 0);
                        }
                    }
                    else
                    {
                        var lineStart = (currentOffset / 16) * 16;
                        newOffset = lineStart + 15;
                    }
                    break;
                case Key.PageUp:
                    newOffset = Math.Max(0, currentOffset - (16 * 10));
                    break;
                case Key.PageDown:
                    newOffset = currentOffset + (16 * 10);
                    break;
                case Key.A when e.KeyModifiers.HasFlag(KeyModifiers.Control):
                    SelectAll();
                    e.Handled = true;
                    return;
                case Key.Escape:
                    ClearSelection();
                    e.Handled = true;
                    return;
                default:
                    handled = false;
                    break;
            }

            if (handled && newOffset != currentOffset && IsValidOffset(newOffset))
            {
                if (e.KeyModifiers.HasFlag(KeyModifiers.Shift))
                {
                    if (viewModel.SelectionStartOffset < 0)
                        viewModel.SelectionStartOffset = currentOffset;
                    viewModel.SelectionEndOffset = newOffset;
                }
                else
                {
                    viewModel.SelectionStartOffset = newOffset;
                    viewModel.SelectionEndOffset = newOffset;
                }
                
                viewModel.SelectedOffset = newOffset;
                UpdateSelectionFromViewModel();
                ScrollToOffset(newOffset);
                e.Handled = true;
            }
        }

        private long GetOffsetFromPosition(Point position)
        {
            if (HexRows == null) return -1;
            var row = (int)(position.Y / RowHeight);
            if (row < 0 || row >= HexRows.Count) return -1;
            
            var column = GetColumnFromX(position.X);
            if (column < 0 || column >= 16) return -1;
            
            var hexRow = HexRows[row];
            if (column < hexRow.Offsets.Length)
            {
                return hexRow.Offsets[column];
            }
            
            return -1;
        }

        private int GetColumnFromX(double x)
        {
            for (int i = 0; i < 16; i++)
            {
                var columnStart = _hexColumnPositions[i];
                var columnEnd = columnStart + ByteWidth;
                
                if (x >= columnStart && x < columnEnd)
                {
                    return i;
                }
            }
            
            return -1;
        }

        private Point GetPositionFromOffset(long offset)
        {
            if (HexRows == null) return new Point(-1, -1);
            for (int rowIndex = 0; rowIndex < HexRows.Count; rowIndex++)
            {
                var row = HexRows[rowIndex];
                for (int colIndex = 0; colIndex < row.Offsets.Length; colIndex++)
                {
                    if (row.Offsets[colIndex] == offset)
                    {
                        var x = _hexColumnPositions[colIndex];
                        var y = rowIndex * RowHeight;
                        return new Point(x, y);
                    }
                }
            }
            
            return new Point(-1, -1);
        }

        private void UpdateSelection()
        {
            if (_selectionCanvas == null || _hexScrollViewer == null) return;

            ClearSelectionRectangles();
            
            if (_selectionStartOffset < 0 || _selectionEndOffset < 0) return;
            
            var selectionStart = Math.Min(_selectionStartOffset, _selectionEndOffset);
            var selectionEnd = Math.Max(_selectionStartOffset, _selectionEndOffset);

            var viewport = _hexScrollViewer.Viewport;
            var scrollOffset = _hexScrollViewer.Offset;

            var firstVisibleRow = (int)(scrollOffset.Y / RowHeight);
            var lastVisibleRow = (int)((scrollOffset.Y + viewport.Height) / RowHeight);

            for (int rowIndex = firstVisibleRow; rowIndex <= lastVisibleRow; rowIndex++)
            {
                if (HexRows == null || rowIndex < 0 || rowIndex >= HexRows.Count) continue;

                var row = HexRows[rowIndex];
                if (row == null) continue;

                var rowStartOffset = row.ByteOffset;
                var rowEndOffset = row.ByteOffset + row.RawBytes.Length - 1;

                if (selectionEnd < rowStartOffset || selectionStart > rowEndOffset)
                {
                    continue;
                }

                var lineSelectionStart = Math.Max(selectionStart, rowStartOffset);
                var lineSelectionEnd = Math.Min(selectionEnd, rowEndOffset);

                var startPosition = GetPositionFromOffset(lineSelectionStart);
                var endPosition = GetPositionFromOffset(lineSelectionEnd);

                if (startPosition.X < 0 || endPosition.X < 0) continue;

                var rect = new Rectangle
                {
                    Width = (endPosition.X - startPosition.X) + ByteWidth,
                    Height = RowHeight,
                    Fill = new SolidColorBrush(Color.FromArgb(80, 76, 81, 191)),
                };

                Canvas.SetLeft(rect, startPosition.X);
                Canvas.SetTop(rect, startPosition.Y);

                _selectionCanvas.Children.Add(rect);
                _selectionRectangles.Add(rect);
            }
        }

        public void UpdateSelectionFromViewModel()
        {
            if (DataContext is HexViewerViewModel viewModel)
            {
                _selectionStartOffset = viewModel.SelectionStartOffset;
                _selectionEndOffset = viewModel.SelectionEndOffset;
                UpdateSelection();
            }
        }

        private void ClearSelectionRectangles()
        {
            if (_selectionCanvas == null) return;
            
            foreach (var rect in _selectionRectangles)
            {
                _selectionCanvas.Children.Remove(rect);
            }
            _selectionRectangles.Clear();
        }

        private void ScrollToOffset(long offset)
        {
            if (_hexRowsContainer is not ListBox listBox) return;

            var rowIndex = (int)(offset / 16);
            if (rowIndex >= 0 && rowIndex < listBox.ItemCount)
            {
                listBox.ScrollIntoView(rowIndex);
            }
        }

        private bool IsValidOffset(long offset)
        {
            return HexRows?.Any(row => row.Offsets.Contains(offset)) ?? false;
        }

        public void SelectAll()
        {
            if (DataContext is HexViewerViewModel viewModel)
            {
                viewModel.SelectAllCommand.Execute(null);
            }
        }

        public void ClearSelection()
        {
            _selectionStartOffset = -1;
            _selectionEndOffset = -1;
            
            if (DataContext is HexViewerViewModel viewModel)
            {
                viewModel.SelectionStartOffset = -1;
                viewModel.SelectionEndOffset = -1;
            }
            
            ClearSelectionRectangles();
        }

        public byte[] GetSelectedBytes()
        {
            if (DataContext is not HexViewerViewModel viewModel || viewModel.SelectionLength == 0)
                return Array.Empty<byte>();

            var start = Math.Min(viewModel.SelectionStartOffset, viewModel.SelectionEndOffset);
            var end = Math.Max(viewModel.SelectionStartOffset, viewModel.SelectionEndOffset);
            
            var result = new List<byte>();
            
            if (HexRows is VirtualizingHexList virtualizingHexList)
            {
                var bytes = virtualizingHexList.ReadRange(start, (int)(end - start + 1));
                result.AddRange(bytes);
            }
            
            return result.ToArray();
        }
    }
}