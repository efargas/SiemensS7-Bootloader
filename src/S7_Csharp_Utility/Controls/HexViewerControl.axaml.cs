using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Controls.Shapes;
using Avalonia.VisualTree;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility.Controls
{
    public partial class HexViewerControl : UserControl
    {
        private ListBox? _hexListBox;
        private Canvas? _selectionCanvas;
        private readonly List<Rectangle> _selectionRectangles = new();
        private bool _isDragging;
        private Point _dragStartPoint;
        private long _selectionStartOffset = -1;
        private long _selectionEndOffset = -1;

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
            Focusable = true;
            KeyDown += OnHexViewerKeyDown;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            _hexListBox = this.FindControl<ListBox>("HexListBox");
            _selectionCanvas = this.FindControl<Canvas>("SelectionCanvas");
        }

        private void OnHexListBoxPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (_hexListBox == null) return;

            var position = e.GetPosition(_hexListBox);
            var offset = GetOffsetFromPosition(position);

            if (offset >= 0)
            {
                _isDragging = true;
                _dragStartPoint = position;
                _selectionStartOffset = offset;
                _selectionEndOffset = offset;

                UpdateSelectionInViewModel();
                e.Pointer.Capture(_hexListBox);
                e.Handled = true;
            }
        }

        private void OnHexListBoxPointerMoved(object? sender, PointerEventArgs e)
        {
            if (_isDragging)
            {
                var position = e.GetPosition(_hexListBox);
                var offset = GetOffsetFromPosition(position);

                if (offset >= 0)
                {
                    _selectionEndOffset = offset;
                    UpdateSelectionInViewModel();
                }
                e.Handled = true;
            }
        }

        private void OnHexListBoxPointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            if (_isDragging)
            {
                _isDragging = false;
                e.Pointer.Capture(null);
                e.Handled = true;
            }
        }

        public void ScrollToOffset(long offset)
        {
            if (_hexListBox == null || HexRows == null) return;

            var rowIndex = (int)(offset / 16);
            if (rowIndex >= 0 && rowIndex < HexRows.Count)
            {
                _hexListBox.ScrollIntoView(HexRows[rowIndex]);
            }
        }

        private void OnHexViewerKeyDown(object? sender, KeyEventArgs e)
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
                case Key.PageUp:
                    newOffset = Math.Max(0, currentOffset - (16 * 10));
                    break;
                case Key.PageDown:
                    newOffset = currentOffset + (16 * 10);
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
                        if (HexRows is VirtualizingHexList list)
                        {
                            newOffset = list.FileSize - 1;
                        }
                    }
                    else
                    {
                        var lineStart = (currentOffset / 16) * 16;
                        newOffset = lineStart + 15;
                    }
                    break;
                default:
                    handled = false;
                    break;
            }

            if (handled && newOffset != currentOffset && IsValidOffset(newOffset))
            {
                viewModel.SelectedOffset = newOffset;
                ScrollToOffset(newOffset);
                e.Handled = true;
            }
        }

        private bool IsValidOffset(long offset)
        {
            if (HexRows is not VirtualizingHexList list) return false;
            return offset >= 0 && offset < list.FileSize;
        }

        private void UpdateSelectionInViewModel()
        {
            if (DataContext is HexViewerViewModel viewModel)
            {
                var start = Math.Min(_selectionStartOffset, _selectionEndOffset);
                var end = Math.Max(_selectionStartOffset, _selectionEndOffset);

                viewModel.SelectionStartOffset = start;
                viewModel.SelectionEndOffset = end;
                viewModel.SelectedOffset = end;

                UpdateSelectionRectangles();
            }
        }

        private void UpdateSelectionRectangles()
        {
            // This method may need to be updated or removed depending on the new selection strategy.
            // For now, it is left empty.
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

        private long GetOffsetFromPosition(Point position)
        {
            if (_hexListBox == null || HexRows == null) return -1;

            var inputElement = _hexListBox.InputHitTest(position);
            if (inputElement == null) return -1;

            var visual = inputElement as Visual;
            if (visual == null) return -1;

            var listBoxItem = visual.FindAncestorOfType<ListBoxItem>();
            if (listBoxItem == null) return -1;

            if (listBoxItem.DataContext is HexViewerService.HexRow row)
            {
                var itemsControl = listBoxItem.FindDescendantOfType<ItemsControl>();
                if (itemsControl != null)
                {
                    var relativePosition = visual.TranslatePoint(position, itemsControl) ?? position;
                    var itemIndex = (int)(relativePosition.X / 24); // Assuming 24 is the width of the hex values
                    if (itemIndex >= 0 && itemIndex < row.Offsets.Length)
                    {
                        return row.Offsets[itemIndex];
                    }
                }
                return row.ByteOffset; // Fallback to row start
            }

            return -1;
        }
    }
}
