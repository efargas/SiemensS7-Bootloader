using Avalonia.Controls;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Services;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// The main window of the application.
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow(MainWindowViewModel viewModel, IViewService viewService)
        {
            InitializeComponent();
            
            DataContext = viewModel;

            if (viewService is ViewService concreteViewService)
            {
                concreteViewService.SetMainWindow(this);
            }
        }
    }
}
