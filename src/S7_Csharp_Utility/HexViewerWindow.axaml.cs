using Avalonia.Controls;
using Avalonia.VisualTree;
using S7_Csharp_Utility.ViewModels;
using System.Collections.Generic;
using System.Linq;

namespace S7_Csharp_Utility
{
    public partial class HexViewerWindow : Window
    {
        private readonly HexViewerViewModel _viewModel;
        private bool _isSyncingScroll;

        public HexViewerWindow() : this(string.Empty) { }

        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _viewModel = new HexViewerViewModel();
            DataContext = _viewModel;
            _ = _viewModel.LoadFileAsync(filePath);

            var hexGrid1 = this.FindControl<DataGrid>("HexDataGrid1");
            var hexGrid2 = this.FindControl<DataGrid>("HexDataGrid2");

            if (hexGrid1 != null && hexGrid2 != null)
            {
                var scrollViewer1 = hexGrid1.FindDescendantOfType<ScrollViewer>();
                var scrollViewer2 = hexGrid2.FindDescendantOfType<ScrollViewer>();

                if (scrollViewer1 != null && scrollViewer2 != null)
                {
                    scrollViewer1.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer1, scrollViewer2);
                    scrollViewer2.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer2, scrollViewer1);
                }

                hexGrid1.SelectionChanged += (s, e) => HexGrid_SelectionChanged(hexGrid1);
                hexGrid2.SelectionChanged += (s, e) => HexGrid_SelectionChanged(hexGrid2);
            }
        }

        private void OnScrollChanged(ScrollViewer source, ScrollViewer target)
        {
            if (_isSyncingScroll) return;

            _isSyncingScroll = true;
            target.Offset = source.Offset;
            _isSyncingScroll = false;
        }

        private void HexGrid_SelectionChanged(DataGrid grid)
        {
            if (grid == null) return;

            var selectedBytes = new List<byte>();
            var selectedRows = grid.SelectedItems.OfType<HexRow>().ToList();

            foreach (var row in selectedRows)
            {
                if (row.Hex == null) continue;
                var hexValues = row.Hex.Split(' ');
                foreach (var hexValue in hexValues)
                {
                    if (byte.TryParse(hexValue, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                    {
                        selectedBytes.Add(b);
                    }
                }
            }

            _viewModel.SelectedBytes = selectedBytes.ToArray();
        }
    }
}