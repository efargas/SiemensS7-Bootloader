using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
    /// <summary>
    /// Efficient hex viewer control using Canvas-based selection instead of buttons.
    /// Provides better performance and smoother drag selection.
    /// </summary>
    public partial class HexViewerControl : UserControl
    {
        private Canvas? _selectionCanvas;
        private ItemsControl? _hexRowsContainer;
        private ScrollViewer? _hexScrollViewer;
        
        // Selection state
        private bool _isDragging;
        private Point _dragStartPoint;
        private long _selectionStartOffset = -1;
        private long _selectionEndOffset = -1;
        private readonly List<Rectangle> _selectionRectangles = new();
        private readonly List<Rectangle> _searchResultRectangles = new();
        
        // Layout constants
        private const double RowHeight = 20;
        private const double ByteWidth = 24;
        private const double OffsetWidth = 70;
        private const double SeparatorWidth = 8;
        private const double AsciiSeparatorWidth = 16;
        
        // Column positions for hex bytes (0-15)
        private readonly double[] _hexColumnPositions = new double[16];

        public static readonly StyledProperty<ObservableCollection<HexViewerService.HexRow>> HexRowsProperty =
            AvaloniaProperty.Register<HexViewerControl, ObservableCollection<HexViewerService.HexRow>>(
                nameof(HexRows), new ObservableCollection<HexViewerService.HexRow>());

        public ObservableCollection<HexViewerService.HexRow> HexRows
        {
            get => GetValue(HexRowsProperty);
            set => SetValue(HexRowsProperty, value);
        }

        public HexViewerControl()
        {
            InitializeComponent();
            InitializeColumnPositions();
            
            // Make the control focusable for keyboard events
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

        /// <summary>
        /// Initialize the column positions for hex bytes
        /// </summary>
        private void InitializeColumnPositions()
        {
            double currentX = OffsetWidth;
            
            // First 8 bytes (00-07)
            for (int i = 0; i < 8; i++)
            {
                _hexColumnPositions[i] = currentX;
                currentX += ByteWidth;
            }
            
            // Add separator
            currentX += SeparatorWidth;
            
            // Next 8 bytes (08-0F)
            for (int i = 8; i < 16; i++)
            {
                _hexColumnPositions[i] = currentX;
                currentX += ByteWidth;
            }
        }

        /// <summary>
        /// Handle pointer pressed events for selection start
        /// </summary>
        private void OnPointerPressed(object sender, PointerPressedEventArgs e)
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
                    // Extend selection from current selected offset
                    _selectionStartOffset = viewModel.SelectedOffset;
                    _selectionEndOffset = offset;
                }
                else if (!modifiers.HasFlag(KeyModifiers.Control))
                {
                    // Start new selection
                    _selectionStartOffset = offset;
                    _selectionEndOffset = offset;
                }
                
                UpdateSelection();
                e.Pointer.Capture(_selectionCanvas);
                e.Handled = true;
            }
        }

        /// <summary>
        /// Handle pointer moved events for drag selection
        /// </summary>
        private void OnPointerMoved(object sender, PointerEventArgs e)
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

        /// <summary>
        /// Handle pointer released events to end selection
        /// </summary>
        private void OnPointerReleased(object sender, PointerReleasedEventArgs e)
        {
            if (_isDragging)
            {
                _isDragging = false;
                e.Pointer.Capture(null);
                
                // Update ViewModel with final selection
                if (DataContext is HexViewerViewModel viewModel)
                {
                    var start = Math.Min(_selectionStartOffset, _selectionEndOffset);
                    var end = Math.Max(_selectionStartOffset, _selectionEndOffset);
                    
                    viewModel.SelectionStartOffset = start;
                    viewModel.SelectionEndOffset = end;
                    viewModel.SelectedOffset = end; // Set cursor to end of selection
                }
                
                e.Handled = true;
            }
        }

        /// <summary>
        /// Handle keyboard navigation
        /// </summary>
        private void OnKeyDown(object sender, KeyEventArgs e)
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
                        newOffset = 0; // Go to beginning of file
                    else
                        newOffset = (currentOffset / 16) * 16; // Go to beginning of line
                    break;
                case Key.End:
                    if (e.KeyModifiers.HasFlag(KeyModifiers.Control))
                    {
                        // Go to end of file
                        var lastRow = viewModel.HexRows1.LastOrDefault();
                        if (lastRow != null)
                        {
                            newOffset = lastRow.Offsets.LastOrDefault(o => o >= 0);
                        }
                    }
                    else
                    {
                        // Go to end of current line
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
                    // Extend selection
                    if (viewModel.SelectionStartOffset < 0)
                        viewModel.SelectionStartOffset = currentOffset;
                    viewModel.SelectionEndOffset = newOffset;
                }
                else
                {
                    // Move cursor
                    viewModel.SelectionStartOffset = newOffset;
                    viewModel.SelectionEndOffset = newOffset;
                }
                
                viewModel.SelectedOffset = newOffset;
                UpdateSelectionFromViewModel();
                ScrollToOffset(newOffset);
                e.Handled = true;
            }
        }

        /// <summary>
        /// Get the byte offset from a canvas position
        /// </summary>
        private long GetOffsetFromPosition(Point position)
        {
            // Calculate row
            var row = (int)(position.Y / RowHeight);
            if (row < 0 || row >= HexRows.Count) return -1;
            
            // Calculate column (byte index within row)
            var column = GetColumnFromX(position.X);
            if (column < 0 || column >= 16) return -1;
            
            // Get the actual offset from the hex row
            var hexRow = HexRows[row];
            if (column < hexRow.Offsets.Length)
            {
                return hexRow.Offsets[column];
            }
            
            return -1;
        }

        /// <summary>
        /// Get the column index from X position
        /// </summary>
        private int GetColumnFromX(double x)
        {
            // Find the closest hex column
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

        /// <summary>
        /// Get the position of a specific offset
        /// </summary>
        private Point GetPositionFromOffset(long offset)
        {
            // Find the row containing this offset
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

        /// <summary>
        /// Update the visual selection based on current selection state
        /// </summary>
        private void UpdateSelection()
        {
            ClearSelectionRectangles();
            
            if (_selectionStartOffset < 0 || _selectionEndOffset < 0) return;
            
            var start = Math.Min(_selectionStartOffset, _selectionEndOffset);
            var end = Math.Max(_selectionStartOffset, _selectionEndOffset);
            
            // Create selection rectangles for the range
            for (long offset = start; offset <= end; offset++)
            {
                var position = GetPositionFromOffset(offset);
                if (position.X >= 0 && position.Y >= 0)
                {
                    var rect = new Rectangle
                    {
                        Width = ByteWidth,
                        Height = RowHeight,
                        Fill = new SolidColorBrush(Color.FromArgb(80, 76, 81, 191)), // Semi-transparent blue
                    };
                    
                    Canvas.SetLeft(rect, position.X);
                    Canvas.SetTop(rect, position.Y);
                    
                    _selectionCanvas.Children.Add(rect);
                    _selectionRectangles.Add(rect);
                }
            }
        }

        /// <summary>
        /// Update selection from ViewModel state
        /// </summary>
        public void UpdateSelectionFromViewModel()
        {
            if (DataContext is HexViewerViewModel viewModel)
            {
                _selectionStartOffset = viewModel.SelectionStartOffset;
                _selectionEndOffset = viewModel.SelectionEndOffset;
                UpdateSelection();
            }
        }

        /// <summary>
        /// Clear all selection rectangles
        /// </summary>
        private void ClearSelectionRectangles()
        {
            if (_selectionCanvas == null) return;
            
            foreach (var rect in _selectionRectangles)
            {
                _selectionCanvas.Children.Remove(rect);
            }
            _selectionRectangles.Clear();
        }

        /// <summary>
        /// Highlight search results
        /// </summary>
        public void HighlightSearchResults(List<long> searchOffsets)
        {
            if (_selectionCanvas == null) return;
            
            // Clear existing search highlights
            foreach (var rect in _searchResultRectangles)
            {
                _selectionCanvas.Children.Remove(rect);
            }
            _searchResultRectangles.Clear();
            
            // Add new search highlights
            foreach (var offset in searchOffsets)
            {
                var position = GetPositionFromOffset(offset);
                if (position.X >= 0 && position.Y >= 0)
                {
                    var rect = new Rectangle
                    {
                        Width = ByteWidth,
                        Height = RowHeight,
                        Fill = new SolidColorBrush(Color.FromArgb(100, 245, 158, 11)), // Semi-transparent orange
                    };
                    
                    Canvas.SetLeft(rect, position.X);
                    Canvas.SetTop(rect, position.Y);
                    
                    _selectionCanvas.Children.Add(rect);
                    _searchResultRectangles.Add(rect);
                }
            }
        }

        /// <summary>
        /// Navigate to a specific offset
        /// </summary>
        public void GoToOffset(long targetOffset)
        {
            if (IsValidOffset(targetOffset))
            {
                if (DataContext is HexViewerViewModel viewModel)
                {
                    viewModel.SelectedOffset = targetOffset;
                    viewModel.SelectionStartOffset = targetOffset;
                    viewModel.SelectionEndOffset = targetOffset;
                    
                    _selectionStartOffset = targetOffset;
                    _selectionEndOffset = targetOffset;
                    
                    UpdateSelection();
                    ScrollToOffset(targetOffset);
                }
            }
        }

        /// <summary>
        /// Scroll to make the specified offset visible
        /// </summary>
        private void ScrollToOffset(long offset)
        {
            if (_hexScrollViewer == null) return;
            
            var position = GetPositionFromOffset(offset);
            if (position.Y >= 0)
            {
                var targetY = position.Y - (_hexScrollViewer.Viewport.Height / 2);
                _hexScrollViewer.Offset = _hexScrollViewer.Offset.WithY(Math.Max(0, targetY));
            }
        }

        /// <summary>
        /// Check if an offset is valid
        /// </summary>
        private bool IsValidOffset(long offset)
        {
            return HexRows.Any(row => row.Offsets.Contains(offset));
        }

        /// <summary>
        /// Select all visible bytes
        /// </summary>
        public void SelectAll()
        {
            if (HexRows.Count == 0) return;
            
            var firstRow = HexRows.First();
            var lastRow = HexRows.Last();
            
            var firstOffset = firstRow.Offsets.FirstOrDefault(o => o >= 0);
            var lastOffset = lastRow.Offsets.LastOrDefault(o => o >= 0);
            
            if (firstOffset >= 0 && lastOffset >= 0)
            {
                _selectionStartOffset = firstOffset;
                _selectionEndOffset = lastOffset;
                
                if (DataContext is HexViewerViewModel viewModel)
                {
                    viewModel.SelectionStartOffset = firstOffset;
                    viewModel.SelectionEndOffset = lastOffset;
                    viewModel.SelectedOffset = firstOffset;
                }
                
                UpdateSelection();
            }
        }

        /// <summary>
        /// Clear all selections
        /// </summary>
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

        /// <summary>
        /// Get the currently selected bytes as a byte array
        /// </summary>
        public byte[] GetSelectedBytes()
        {
            if (DataContext is not HexViewerViewModel viewModel || viewModel.SelectionLength == 0)
                return Array.Empty<byte>();

            var start = Math.Min(viewModel.SelectionStartOffset, viewModel.SelectionEndOffset);
            var end = Math.Max(viewModel.SelectionStartOffset, viewModel.SelectionEndOffset);
            
            var result = new List<byte>();
            
            for (long offset = start; offset <= end; offset++)
            {
                // Find the byte at this offset
                foreach (var row in HexRows)
                {
                    for (int i = 0; i < row.Offsets.Length; i++)
                    {
                        if (row.Offsets[i] == offset && i < row.RawBytes.Length)
                        {
                            result.Add(row.RawBytes[i]);
                            break;
                        }
                    }
                }
            }
            
            return result.ToArray();
        }
    }
}