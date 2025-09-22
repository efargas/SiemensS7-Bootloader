using Avalonia.Controls;
using Avalonia.Interactivity;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility.Views
{
    public partial class ComparisonResultWindow : Window
    {
        public ComparisonResultWindow()
        {
            InitializeComponent();
        }

        public ComparisonResultWindow(string comparisonResult) : this()
        {
            DataContext = new ComparisonResultViewModel(comparisonResult);
        }

        private void CloseButton_Click(object? sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}