using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.VisualTree;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Controls;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// Optimized hex viewer window with side-by-side comparison and data analysis.
    /// </summary>
    public partial class HexViewerWindow : Window
    {
        private readonly HexViewerViewModel _viewModel;
        private bool _isSyncingScroll;

        /// <summary>
        /// Initializes a new instance of the <see cref="HexViewerWindow"/> class.
        /// </summary>
        public HexViewerWindow() : this(string.Empty) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="HexViewerWindow"/> class with a file path.
        /// </summary>
        /// <param name="filePath">The initial file path to load.</param>
        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _viewModel = new HexViewerViewModel(new DialogService(this));
            DataContext = _viewModel;

            // Load initial file if provided
            if (!string.IsNullOrEmpty(filePath))
            {
                _ = _viewModel.LoadFileAsync(filePath);
            }

            SetupControlSynchronization();
        }

        /// <summary>
        /// Sets up scroll and selection synchronization between the hex viewer controls.
        /// </summary>
        private void SetupControlSynchronization()
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            var hexGrid2 = this.FindControl<DataGrid>("HexDataGrid2");

            if (customHexViewer1 != null)
            {
                // Setup scroll synchronization for the custom control
                var scrollViewer1 = customHexViewer1.FindDescendantOfType<ScrollViewer>();
                
                if (hexGrid2 != null)
                {
                    var scrollViewer2 = hexGrid2.FindDescendantOfType<ScrollViewer>();
                    
                    if (scrollViewer1 != null && scrollViewer2 != null)
                    {
                        scrollViewer1.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer1, scrollViewer2);
                        scrollViewer2.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer2, scrollViewer1);
                    }

                    // Setup selection handling for the DataGrid (second panel)
                    hexGrid2.SelectionChanged += (s, e) => HexGrid_SelectionChanged(hexGrid2);
                }

                // Subscribe to ViewModel property changes to update the custom control
                _viewModel.PropertyChanged += (s, e) =>
                {
                    if (e.PropertyName == nameof(HexViewerViewModel.SelectedOffset))
                    {
                        customHexViewer1.UpdateButtonStyles();
                    }
                    else if (e.PropertyName == nameof(HexViewerViewModel.SearchResults))
                    {
                        customHexViewer1.HighlightSearchResults(_viewModel.SearchResults);
                    }
                };
            }
        }

        /// <summary>
        /// Handles scroll synchronization between hex controls.
        /// </summary>
        /// <param name="source">The source scroll viewer.</param>
        /// <param name="target">The target scroll viewer to synchronize.</param>
        private void OnScrollChanged(ScrollViewer source, ScrollViewer target)
        {
            if (_isSyncingScroll || !_viewModel.IsSynchronizationEnabled) return;

            _isSyncingScroll = true;
            try
            {
                target.Offset = source.Offset;
            }
            finally
            {
                _isSyncingScroll = false;
            }
        }

        /// <summary>
        /// Handles selection changes in hex grids and updates the data inspector.
        /// </summary>
        /// <param name="grid">The grid that had its selection changed.</param>
        private void HexGrid_SelectionChanged(DataGrid grid)
        {
            if (grid?.SelectedItem is not HexViewerService.HexRow selectedRow)
            {
                return;
            }

            try
            {
                // Update the selected offset for the data inspector
                _viewModel.SelectedOffset = selectedRow.ByteOffset;

                // Synchronize selection between controls if enabled
                if (_viewModel.IsSynchronizationEnabled && _viewModel.IsSideBySideMode)
                {
                    SynchronizeSelectionByAddress(selectedRow.ByteOffset);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling selection change: {ex.Message}");
            }
        }

        /// <summary>
        /// Synchronizes selection between controls based on address/offset.
        /// </summary>
        /// <param name="targetOffset">The target offset to synchronize to.</param>
        private void SynchronizeSelectionByAddress(long targetOffset)
        {
            try
            {
                var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
                var hexGrid2 = this.FindControl<DataGrid>("HexDataGrid2");

                if (customHexViewer1 != null)
                {
                    // Update the custom hex viewer selection
                    customHexViewer1.GoToOffset(targetOffset);
                }

                if (hexGrid2 != null)
                {
                    // Find the row with matching offset in the second grid
                    var matchingRow = _viewModel.HexRows2.FirstOrDefault(row => row.ByteOffset == targetOffset);
                    if (matchingRow != null)
                    {
                        // Temporarily disable selection change handling to avoid recursion
                        _isSyncingScroll = true;
                        try
                        {
                            hexGrid2.SelectedItem = matchingRow;
                            hexGrid2.ScrollIntoView(matchingRow, hexGrid2.Columns.FirstOrDefault());
                        }
                        finally
                        {
                            _isSyncingScroll = false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error synchronizing selection: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the Go To Offset command by navigating to the specified offset in the custom control.
        /// </summary>
        public void GoToOffset(long offset)
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            customHexViewer1?.GoToOffset(offset);
        }

        /// <summary>
        /// Handles search result highlighting in the custom control.
        /// </summary>
        public void HighlightSearchResults(System.Collections.Generic.List<long> searchOffsets)
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            customHexViewer1?.HighlightSearchResults(searchOffsets);
        }

        /// <summary>
        /// Gets the selected bytes from the custom hex viewer control.
        /// </summary>
        public byte[] GetSelectedBytes()
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            return customHexViewer1?.GetSelectedBytes() ?? Array.Empty<byte>();
        }

        /// <summary>
        /// Disposes of resources when the window is closed.
        /// </summary>
        protected override void OnClosed(EventArgs e)
        {
            _viewModel?.Dispose();
            base.OnClosed(e);
        }
    }
}