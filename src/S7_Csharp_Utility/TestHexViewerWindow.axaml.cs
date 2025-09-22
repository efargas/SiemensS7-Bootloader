using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using S7_Csharp_Utility.ViewModels;
using S7_Csharp_Utility.Services;

namespace S7_Csharp_Utility
{
    public partial class TestHexViewerWindow : Window
    {
        public TestHexViewerWindow()
        {
            InitializeComponent();
            
            // Create a test ViewModel with DialogService
            var dialogService = new DialogService();
            var viewModel = new HexViewerViewModel(dialogService);
            DataContext = viewModel;
            
            // Load test file automatically
            _ = LoadTestFileAsync(viewModel);
        }
        
        private async Task LoadTestFileAsync(HexViewerViewModel viewModel)
        {
            try
            {
                // Run simple component test first
                await SimpleHexTest.RunTestAsync();
                
                // Load test file
                var testFile = "/home/miniyo88/Documents/Github/SiemensS7-Bootloader/test_hex_viewer_new.bin";
                if (System.IO.File.Exists(testFile))
                {
                    await viewModel.LoadFileAsync(testFile, 1);
                    Console.WriteLine($"✅ Test file loaded into UI: {viewModel.HexRows1.Count} rows");
                }
                else
                {
                    Console.WriteLine("⚠️ Test file not found, creating a new one...");
                    // Create a simple test file
                    var testData = "Hello World!\nThis is a test file for the hex viewer.\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
                    await System.IO.File.WriteAllTextAsync(testFile, testData);
                    await viewModel.LoadFileAsync(testFile, 1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error loading test file: {ex.Message}");
            }
        }
    }
}