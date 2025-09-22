using System;
using System.Threading.Tasks;
using S7_Csharp_Utility.Services;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Testing HexViewerService...");
        
        var service = new HexViewerService();
        var testFile = "/home/miniyo88/Documents/Github/SiemensS7-Bootloader/test_hex_viewer_new.bin";
        
        try
        {
            // Test file info
            var fileInfo = await service.GetFileInfoAsync(testFile);
            Console.WriteLine($"File: {fileInfo.FileName}");
            Console.WriteLine($"Size: {fileInfo.FormattedSize}");
            Console.WriteLine($"MD5: {fileInfo.MD5Hash}");
            
            // Test hex data loading
            var hexRows = await service.LoadHexDataAsync(testFile, 0, 10);
            Console.WriteLine($"\nLoaded {hexRows.Count} hex rows:");
            
            foreach (var row in hexRows.Take(5))
            {
                Console.WriteLine($"{row.Address}: {string.Join(" ", row.Bytes.Where(b => !string.IsNullOrEmpty(b)))} | {row.Ascii}");
            }
            
            Console.WriteLine("\n✅ HexViewerService test completed successfully!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }
}