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

            // Connect ListBox references to logging services for scroll control
            Loaded += (sender, e) =>
            {
                var logListBox = this.FindControl<ListBox>("LogListBox");
                var socatLogListBox = this.FindControl<ListBox>("SocatLogListBox");

                if (logListBox != null && viewModel.Logging != null)
                {
                    viewModel.Logging.LogListBox = logListBox;
                }

                if (socatLogListBox != null && viewModel.SocatLogging != null)
                {
                    viewModel.SocatLogging.LogListBox = socatLogListBox;
                }
            };
        }
    }
}
