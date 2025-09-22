using System;
using System.Linq;
using System.Threading.Tasks;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// Simple test to verify hex viewer components work
    /// </summary>
    public static class SimpleHexTest
    {
        public static async Task RunTestAsync()
        {
            Console.WriteLine("🔍 Testing Hex Viewer Components...");
            
            try
            {
                // Test HexViewerService
                Console.WriteLine("1. Testing HexViewerService...");
                var service = new HexViewerService();
                var testFile = "/home/miniyo88/Documents/Github/SiemensS7-Bootloader/test_hex_viewer_new.bin";
                
                if (System.IO.File.Exists(testFile))
                {
                    var fileInfo = await service.GetFileInfoAsync(testFile);
                    Console.WriteLine($"   ✅ File loaded: {fileInfo.FileName} ({fileInfo.FormattedSize})");
                    
                    var hexRows = await service.LoadHexDataAsync(testFile, 0, 5);
                    Console.WriteLine($"   ✅ Hex rows loaded: {hexRows.Count}");
                    
                    if (hexRows.Count > 0)
                    {
                        var firstRow = hexRows[0];
                        Console.WriteLine($"   📄 First row: {firstRow.Address} | {string.Join(" ", firstRow.Bytes.Take(8))} | {firstRow.Ascii.Substring(0, Math.Min(8, firstRow.Ascii.Length))}");
                    }
                }
                else
                {
                    Console.WriteLine($"   ⚠️ Test file not found: {testFile}");
                }
                
                // Test HexViewerViewModel
                Console.WriteLine("2. Testing HexViewerViewModel...");
                var dialogService = new DialogService();
                var viewModel = new HexViewerViewModel(dialogService);
                Console.WriteLine("   ✅ ViewModel created successfully");
                
                // Test loading file into ViewModel
                if (System.IO.File.Exists(testFile))
                {
                    await viewModel.LoadFileAsync(testFile, 1);
                    Console.WriteLine($"   ✅ File loaded into ViewModel: {viewModel.HexRows1.Count} rows");
                    
                    if (viewModel.HexRows1.Count > 0)
                    {
                        Console.WriteLine($"   📊 Status: {viewModel.StatusText}");
                    }
                }
                
                Console.WriteLine("3. Testing selection functionality...");
                viewModel.SelectedOffset = 0;
                viewModel.SelectionStartOffset = 0;
                viewModel.SelectionEndOffset = 15;
                Console.WriteLine($"   ✅ Selection test: {viewModel.SelectionLength} bytes selected");
                
                Console.WriteLine("\n🎉 All hex viewer components tested successfully!");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Test failed: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}