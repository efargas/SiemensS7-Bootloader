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
        private bool _isSyncingScroll;

        public HexViewerWindow() : this(string.Empty) { }

        public HexViewerWindow(string filePath)
        {
            InitializeComponent();
            _viewModel = new HexViewerViewModel(new DialogService());
            DataContext = _viewModel;

            if (!string.IsNullOrEmpty(filePath))
            {
                _ = _viewModel.LoadFileAsync(filePath);
            }

            SetupControlSynchronization();
        }

        private void SetupControlSynchronization()
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            var customHexViewer2 = this.FindControl<HexViewerControl>("CustomHexViewer2");

            if (customHexViewer1 != null)
            {
                var scrollViewer1 = customHexViewer1.FindDescendantOfType<ScrollViewer>();
                
                if (customHexViewer2 != null)
                {
                    var scrollViewer2 = customHexViewer2.FindDescendantOfType<ScrollViewer>();
                    
                    if (scrollViewer1 != null && scrollViewer2 != null)
                    {
                        scrollViewer1.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer1, scrollViewer2);
                        scrollViewer2.ScrollChanged += (s, e) => OnScrollChanged(scrollViewer2, scrollViewer1);
                    }
                }

                _viewModel.PropertyChanged += (s, e) =>
                {
                    if (e.PropertyName == nameof(HexViewerViewModel.SelectedOffset) ||
                        e.PropertyName == nameof(HexViewerViewModel.SelectionStartOffset) ||
                        e.PropertyName == nameof(HexViewerViewModel.SelectionEndOffset))
                    {
                        customHexViewer1.UpdateSelectionFromViewModel();
                        customHexViewer2?.UpdateSelectionFromViewModel();
                    }
                };
            }
        }

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

        public byte[] GetSelectedBytes()
        {
            var customHexViewer1 = this.FindControl<HexViewerControl>("CustomHexViewer1");
            return customHexViewer1?.GetSelectedBytes() ?? Array.Empty<byte>();
        }

        protected override void OnClosed(EventArgs e)
        {
            _viewModel?.Dispose();
            base.OnClosed(e);
        }
    }
}