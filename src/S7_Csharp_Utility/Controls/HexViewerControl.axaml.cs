using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.VisualTree;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility.Controls
{
    /// <summary>
    /// Custom hex viewer control with improved layout and multi-selection support.
    /// </summary>
    public partial class HexViewerControl : UserControl
    {
        private readonly HashSet<Button> _selectedButtons = new();
        private readonly Dictionary<long, Button> _offsetToButtonMap = new();
        private Button? _lastSelectedButton;
        private bool _shiftPressed;
        private bool _ctrlPressed;
        private long _dragStartOffset = -1;
        private long _lastHoveredOffset = -1;

        public static readonly StyledProperty<ObservableCollection<HexViewerService.HexRow>> HexRowsProperty =
            AvaloniaProperty.Register<HexViewerControl, ObservableCollection<HexViewerService.HexRow>>(
                nameof(HexRows), new ObservableCollection<HexViewerService.HexRow>());

        public ObservableCollection<HexViewerService.HexRow> HexRows
        {
            get => GetValue(HexRowsProperty);
            set => SetValue(HexRowsProperty, value);
        }

        /// <summary>
        /// Command to handle hex cell clicks - exposed as a property for XAML binding
        /// </summary>
        public ICommand HexCellClickCommand { get; }

        public HexViewerControl()
        {
            // Initialize the command before calling InitializeComponent
            HexCellClickCommand = new RelayCommand(param => HandleHexCellClickCommand(param));
            
            InitializeComponent();
            
            // Handle keyboard events for modifier keys
            KeyDown += OnKeyDown;
            KeyUp += OnKeyUp;
            
            // Make the control focusable to receive keyboard events
            Focusable = true;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        /// <summary>
        /// Command handler that bridges to the actual hex cell click logic
        /// </summary>
        private void HandleHexCellClickCommand(object? parameter)
        {
            if (parameter is long offset)
            {
                // Find the button that was clicked - we need to get it from the visual tree
                var button = FindButtonForOffset(offset);
                if (button != null)
                {
                    HandleHexCellClick(button, offset);
                    
                    // Setup drag selection
                    if (!_ctrlPressed && !_shiftPressed)
                    {
                        _dragStartOffset = offset;
                    }
                }
                
                // Also notify the parent ViewModel if it exists
                if (Parent?.DataContext is HexViewerViewModel viewModel)
                {
                    viewModel.SelectedOffset = offset;
                }
            }
        }

        /// <summary>
        /// Handles mouse enter events for drag selection
        /// </summary>
        public void HandleMouseEnter(long offset)
        {
            if (_dragStartOffset >= 0 && offset != _lastHoveredOffset)
            {
                _lastHoveredOffset = offset;
                
                // Perform drag selection
                if (!_ctrlPressed && !_shiftPressed)
                {
                    SelectDragRange(_dragStartOffset, offset);
                }
            }
        }

        /// <summary>
        /// Handles mouse up events to end drag selection
        /// </summary>
        public void HandleMouseUp()
        {
            _dragStartOffset = -1;
            _lastHoveredOffset = -1;
        }

        /// <summary>
        /// Selects a range during drag operation
        /// </summary>
        private void SelectDragRange(long startOffset, long endOffset)
        {
            ClearSelection();
            
            var start = Math.Min(startOffset, endOffset);
            var end = Math.Max(startOffset, endOffset);
            
            var allButtons = GetAllHexButtons();
            foreach (var button in allButtons)
            {
                if (button.CommandParameter is long offset && offset >= start && offset <= end)
                {
                    SelectButton(button, offset);
                }
            }
            
            UpdateViewModelSelection();
        }

        /// <summary>
        /// Finds the button associated with a specific offset
        /// </summary>
        private Button? FindButtonForOffset(long offset)
        {
            var allButtons = GetAllHexButtons();
            return allButtons.FirstOrDefault(b => b.CommandParameter is long buttonOffset && buttonOffset == offset);
        }

        private void OnKeyDown(object? sender, KeyEventArgs e)
        {
            _shiftPressed = e.KeyModifiers.HasFlag(KeyModifiers.Shift);
            _ctrlPressed = e.KeyModifiers.HasFlag(KeyModifiers.Control);
            
            // Handle keyboard navigation
            HandleKeyboardNavigation(e);
        }

        private void OnKeyUp(object? sender, KeyEventArgs e)
        {
            _shiftPressed = e.KeyModifiers.HasFlag(KeyModifiers.Shift);
            _ctrlPressed = e.KeyModifiers.HasFlag(KeyModifiers.Control);
        }

        /// <summary>
        /// Handles keyboard navigation within the hex viewer
        /// </summary>
        private void HandleKeyboardNavigation(KeyEventArgs e)
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
                    if (_ctrlPressed)
                        newOffset = 0; // Go to beginning of file
                    else
                        newOffset = (currentOffset / 16) * 16; // Go to beginning of line
                    break;
                case Key.End:
                    if (_ctrlPressed)
                    {
                        // Go to end of file - find last valid offset
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
                        newOffset = Math.Min(lineStart + 15, currentOffset + (15 - (currentOffset % 16)));
                    }
                    break;
                case Key.PageUp:
                    newOffset = Math.Max(0, currentOffset - (16 * 10)); // Move up 10 rows
                    break;
                case Key.PageDown:
                    newOffset = currentOffset + (16 * 10); // Move down 10 rows
                    break;
                case Key.A when _ctrlPressed:
                    SelectAll();
                    e.Handled = true;
                    return;
                case Key.Escape:
                    ClearAllSelections();
                    e.Handled = true;
                    return;
                default:
                    handled = false;
                    break;
            }

            if (handled && newOffset != currentOffset)
            {
                // Validate the new offset exists
                if (IsValidOffset(newOffset))
                {
                    var button = FindButtonForOffset(newOffset);
                    if (button != null)
                    {
                        if (_shiftPressed && _lastSelectedButton != null)
                        {
                            // Extend selection
                            SelectRange(_lastSelectedButton, button);
                        }
                        else
                        {
                            // Move selection
                            ClearSelection();
                            SelectButton(button, newOffset);
                            _lastSelectedButton = button;
                        }
                        
                        viewModel.SelectedOffset = newOffset;
                        UpdateViewModelSelection();
                        
                        // Scroll to make the selected byte visible
                        ScrollToOffset(newOffset);
                    }
                }
                e.Handled = true;
            }
        }

        /// <summary>
        /// Checks if an offset is valid (exists in the current data)
        /// </summary>
        private bool IsValidOffset(long offset)
        {
            if (DataContext is not HexViewerViewModel viewModel) return false;
            
            return viewModel.HexRows1.Any(row => row.Offsets.Contains(offset));
        }

        /// <summary>
        /// Scrolls the view to make the specified offset visible
        /// </summary>
        private void ScrollToOffset(long offset)
        {
            var scrollViewer = this.FindControl<ScrollViewer>("HexScrollViewer");
            if (scrollViewer == null) return;

            // Calculate which row contains this offset
            var rowIndex = (int)(offset / 16);
            var rowHeight = 20; // Height of each row
            var targetY = rowIndex * rowHeight;

            // Scroll to make the row visible
            scrollViewer.Offset = scrollViewer.Offset.WithY(targetY);
        }

        /// <summary>
        /// Handles hex cell button clicks with multi-selection support.
        /// </summary>
        public void HandleHexCellClick(Button button, long offset)
        {
            if (offset < 0) return;

            // Update the ViewModel's selected offset
            if (DataContext is HexViewerViewModel viewModel)
            {
                viewModel.SelectedOffset = offset;
            }

            if (_ctrlPressed)
            {
                // Ctrl+Click: Toggle selection
                ToggleButtonSelection(button, offset);
            }
            else if (_shiftPressed && _lastSelectedButton != null)
            {
                // Shift+Click: Range selection
                SelectRange(_lastSelectedButton, button);
            }
            else
            {
                // Normal click: Single selection
                ClearSelection();
                SelectButton(button, offset);
            }

            _lastSelectedButton = button;
            UpdateViewModelSelection();
        }

        private void ToggleButtonSelection(Button button, long offset)
        {
            if (_selectedButtons.Contains(button))
            {
                DeselectButton(button);
            }
            else
            {
                SelectButton(button, offset);
            }
        }

        private void SelectRange(Button startButton, Button endButton)
        {
            ClearSelection();
            
            // Find all buttons between start and end
            var allButtons = GetAllHexButtons();
            var startIndex = allButtons.IndexOf(startButton);
            var endIndex = allButtons.IndexOf(endButton);
            
            if (startIndex >= 0 && endIndex >= 0)
            {
                var minIndex = Math.Min(startIndex, endIndex);
                var maxIndex = Math.Max(startIndex, endIndex);
                
                for (int i = minIndex; i <= maxIndex; i++)
                {
                    var button = allButtons[i];
                    if (button.CommandParameter is long offset && offset >= 0)
                    {
                        SelectButton(button, offset);
                    }
                }
            }
        }

        private void SelectButton(Button button, long offset)
        {
            _selectedButtons.Add(button);
            button.Classes.Add("Selected");
        }

        private void DeselectButton(Button button)
        {
            _selectedButtons.Remove(button);
            button.Classes.Remove("Selected");
            button.Classes.Remove("RangeSelected");
        }

        private void ClearSelection()
        {
            foreach (var button in _selectedButtons.ToList())
            {
                DeselectButton(button);
            }
            _selectedButtons.Clear();
        }

        private List<Button> GetAllHexButtons()
        {
            var buttons = new List<Button>();
            var itemsControl = this.FindControl<ItemsControl>("HexRowsContainer");
            
            if (itemsControl != null)
            {
                for (int i = 0; i < itemsControl.ItemCount; i++)
                {
                    var container = itemsControl.ContainerFromIndex(i);
                    if (container != null)
                    {
                        var hexButtons = container.GetVisualDescendants().OfType<Button>()
                            .Where(b => b.Classes.Contains("HexCell")).ToList();
                        buttons.AddRange(hexButtons);
                    }
                }
            }
            
            return buttons;
        }

        private void UpdateViewModelSelection()
        {
            if (DataContext is HexViewerViewModel viewModel)
            {
                var selectedOffsets = _selectedButtons
                    .Where(b => b.CommandParameter is long offset && offset >= 0)
                    .Select(b => (long)b.CommandParameter!)
                    .OrderBy(o => o)
                    .ToList();

                if (selectedOffsets.Count > 0)
                {
                    viewModel.SelectionStartOffset = selectedOffsets.First();
                    viewModel.SelectionEndOffset = selectedOffsets.Last();
                }
                else
                {
                    viewModel.SelectionStartOffset = -1;
                    viewModel.SelectionEndOffset = -1;
                }
            }
        }

        /// <summary>
        /// Updates button styles based on current selection state.
        /// </summary>
        public void UpdateButtonStyles()
        {
            if (DataContext is not HexViewerViewModel viewModel) return;

            var allButtons = GetAllHexButtons();
            
            foreach (var button in allButtons)
            {
                if (button.CommandParameter is long offset && offset >= 0)
                {
                    // Remove all selection classes first
                    button.Classes.Remove("Selected");
                    button.Classes.Remove("RangeSelected");
                    
                    // Apply appropriate style based on selection state
                    if (offset == viewModel.SelectedOffset)
                    {
                        button.Classes.Add("Selected");
                    }
                    else if (viewModel.IsOffsetInSelection(offset))
                    {
                        button.Classes.Add("RangeSelected");
                    }
                }
            }
        }

        /// <summary>
        /// Selects all visible hex bytes.
        /// </summary>
        public void SelectAll()
        {
            ClearSelection();
            var allButtons = GetAllHexButtons();
            
            foreach (var button in allButtons)
            {
                if (button.CommandParameter is long offset && offset >= 0)
                {
                    SelectButton(button, offset);
                }
            }
            
            if (allButtons.Count > 0)
            {
                _lastSelectedButton = allButtons.Last();
            }
            
            UpdateViewModelSelection();
        }

        /// <summary>
        /// Clears all selections.
        /// </summary>
        public void ClearAllSelections()
        {
            ClearSelection();
            _lastSelectedButton = null;
            UpdateViewModelSelection();
        }

        /// <summary>
        /// Event handler for pointer entered on hex cells
        /// </summary>
        private void HexCell_PointerEntered(object? sender, PointerEventArgs e)
        {
            if (sender is Button button && button.CommandParameter is long offset)
            {
                HandleMouseEnter(offset);
            }
        }

        /// <summary>
        /// Event handler for pointer released on hex cells
        /// </summary>
        private void HexCell_PointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            HandleMouseUp();
        }

        /// <summary>
        /// Finds a specific byte offset and scrolls to it
        /// </summary>
        public void GoToOffset(long targetOffset)
        {
            if (IsValidOffset(targetOffset))
            {
                var button = FindButtonForOffset(targetOffset);
                if (button != null)
                {
                    ClearSelection();
                    SelectButton(button, targetOffset);
                    _lastSelectedButton = button;
                    
                    if (DataContext is HexViewerViewModel viewModel)
                    {
                        viewModel.SelectedOffset = targetOffset;
                    }
                    
                    UpdateViewModelSelection();
                    ScrollToOffset(targetOffset);
                }
            }
        }

        /// <summary>
        /// Highlights search results
        /// </summary>
        public void HighlightSearchResults(List<long> searchOffsets)
        {
            var allButtons = GetAllHexButtons();
            
            // Clear existing search highlights
            foreach (var button in allButtons)
            {
                button.Classes.Remove("SearchResult");
            }
            
            // Add search result highlights
            foreach (var offset in searchOffsets)
            {
                var button = FindButtonForOffset(offset);
                if (button != null)
                {
                    button.Classes.Add("SearchResult");
                }
            }
        }

        /// <summary>
        /// Gets the currently selected bytes as a byte array
        /// </summary>
        public byte[] GetSelectedBytes()
        {
            if (DataContext is not HexViewerViewModel viewModel || viewModel.SelectionLength == 0)
                return Array.Empty<byte>();

            var selectedOffsets = _selectedButtons
                .Where(b => b.CommandParameter is long offset && offset >= 0)
                .Select(b => (long)b.CommandParameter!)
                .OrderBy(o => o)
                .ToList();

            if (selectedOffsets.Count == 0) return Array.Empty<byte>();

            var result = new List<byte>();
            
            // Find the bytes from the hex rows
            foreach (var offset in selectedOffsets)
            {
                var row = viewModel.HexRows1.FirstOrDefault(r => r.Offsets.Contains(offset));
                if (row != null)
                {
                    var index = Array.IndexOf(row.Offsets, offset);
                    if (index >= 0 && index < row.RawBytes.Length)
                    {
                        result.Add(row.RawBytes[index]);
                    }
                }
            }
            
            return result.ToArray();
        }
    }
}