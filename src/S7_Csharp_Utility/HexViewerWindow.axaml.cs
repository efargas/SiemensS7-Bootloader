using Avalonia.Controls;
using S7_Csharp_Utility.ViewModels;
using System.Collections.Generic;
using System.Linq;

namespace S7_Csharp_Utility
{
    public partial class HexViewerWindow : Window
    {
        private readonly HexViewerViewModel _viewModel;

        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _viewModel = new HexViewerViewModel();
            DataContext = _viewModel;
            _ = _viewModel.LoadFileAsync(filePath);

            var hexGrid = this.FindControl<DataGrid>("HexDataGrid");
            if (hexGrid != null)
            {
                hexGrid.SelectionChanged += HexGrid_SelectionChanged;
            }
        }

        private void HexGrid_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            var grid = sender as DataGrid;
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