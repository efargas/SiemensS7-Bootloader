using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// Simple test class to verify the custom HexViewerControl works
    /// </summary>
    public static class TestHexViewer
    {
        public static async Task TestCustomHexViewerAsync()
        {
            try
            {
                // Create test window
                var window = new TestHexViewerWindow();
                
                // Show the window
                if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && desktop.MainWindow != null)
                {
                    await window.ShowDialog(desktop.MainWindow);
                }
                else
                {
                    window.Show();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing hex viewer: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
        
        /// <summary>
        /// Creates a test HexViewerViewModel with some sample data
        /// </summary>
        public static async Task<HexViewerViewModel> CreateTestViewModelAsync()
        {
            var dialogService = new DialogService();
            var viewModel = new HexViewerViewModel(dialogService);
            
            // Load a test file if it exists
            var testFile = "/home/miniyo88/Documents/Github/SiemensS7-Bootloader/test_hex_viewer.bin";
            if (System.IO.File.Exists(testFile))
            {
                await viewModel.LoadFileAsync(testFile, 1);
            }
            
            return viewModel;
        }
    }
}