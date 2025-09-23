using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.VisualTree;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Controls;

namespace S7_Csharp_Utility
{
    public partial class HexViewerWindow : Window
    {
        private readonly HexViewerViewModel _viewModel;

        public HexViewerWindow() : this(string.Empty) { }

        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _viewModel = new HexViewerViewModel(new DialogService());
            DataContext = _viewModel;

            if (!string.IsNullOrEmpty(filePath))
            {
                _ = _viewModel.LoadFileAsync(1, filePath);
            }

            SetupControlSynchronization();
        }

        private void SetupControlSynchronization()
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            var customHexViewer2 = this.FindControl<HexViewerControl>("CustomHexViewer2");

            if (customHexViewer1 != null)
            {
                _viewModel.NavigateToOffsetRequested += (offset) =>
                {
                    customHexViewer1.ScrollToOffset(offset);
                    if (customHexViewer2 != null)
                    {
                        customHexViewer2.ScrollToOffset(offset);
                    }
                };
            }
        }


        protected override void OnClosed(EventArgs e)
        {
            _viewModel?.Dispose();
            base.OnClosed(e);
        }
    }
}