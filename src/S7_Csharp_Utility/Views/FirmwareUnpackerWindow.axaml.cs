using Avalonia.Controls;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility
{
    public partial class FirmwareUnpackerWindow : Window
    {
        public FirmwareUnpackerWindow() : this(null, null) { }

        public FirmwareUnpackerWindow(string? extractionPath = null, Interfaces.IDialogService? dialogService = null)
        {
            InitializeComponent();
            DataContext = new FirmwareUnpackerViewModel(dialogService, extractionPath);
        }
    }
}
