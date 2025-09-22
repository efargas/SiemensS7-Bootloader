using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.VisualTree;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Services;

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

            SetupGridSynchronization();
        }

        /// <summary>
        /// Sets up scroll and selection synchronization between the two hex grids.
        /// </summary>
        private void SetupGridSynchronization()
        {
            var hexGrid1 = this.FindControl<DataGrid>("HexDataGrid1");
            var hexGrid2 = this.FindControl<DataGrid>("HexDataGrid2");

            if (hexGrid1 != null && hexGrid2 != null)
            {
                // Setup scroll synchronization
                var scrollViewer1 = hexGrid1.FindDescendantOfType<ScrollViewer>();
                var scrollViewer2 = hexGrid2.FindDescendantOfType<ScrollViewer>();

                if (scrollViewer1 != null && scrollViewer2 != null)
                {
                    scrollViewer1.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer1, scrollViewer2);
                    scrollViewer2.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer2, scrollViewer1);
                }

                // Setup selection handling
                hexGrid1.SelectionChanged += (s, e) => HexGrid_SelectionChanged(hexGrid1);
                hexGrid2.SelectionChanged += (s, e) => HexGrid_SelectionChanged(hexGrid2);
            }
        }

        /// <summary>
        /// Handles scroll synchronization between hex grids.
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

                // Synchronize selection between grids if enabled
                if (_viewModel.IsSynchronizationEnabled && _viewModel.IsSideBySideMode)
                {
                    SynchronizeSelectionByAddress(selectedRow.ByteOffset, grid);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling selection change: {ex.Message}");
            }
        }

        /// <summary>
        /// Synchronizes selection between grids based on address/offset.
        /// </summary>
        /// <param name="targetOffset">The target offset to synchronize to.</param>
        /// <param name="sourceGrid">The source grid to avoid circular updates.</param>
        private void SynchronizeSelectionByAddress(long targetOffset, DataGrid sourceGrid)
        {
            try
            {
                var hexGrid1 = this.FindControl<DataGrid>("HexDataGrid1");
                var hexGrid2 = this.FindControl<DataGrid>("HexDataGrid2");

                if (hexGrid1 == null || hexGrid2 == null) return;

                var targetGrid = sourceGrid == hexGrid1 ? hexGrid2 : hexGrid1;
                var targetCollection = sourceGrid == hexGrid1 ? _viewModel.HexRows2 : _viewModel.HexRows1;

                // Find the row with matching offset in the target grid
                var matchingRow = targetCollection.FirstOrDefault(row => row.ByteOffset == targetOffset);
                if (matchingRow != null)
                {
                    // Temporarily disable selection change handling to avoid recursion
                    _isSyncingScroll = true;
                    try
                    {
                        targetGrid.SelectedItem = matchingRow;
                        targetGrid.ScrollIntoView(matchingRow, targetGrid.Columns.FirstOrDefault());
                    }
                    finally
                    {
                        _isSyncingScroll = false;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error synchronizing selection: {ex.Message}");
            }
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