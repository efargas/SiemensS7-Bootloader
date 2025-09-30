using S7.Utils;
using S7_Csharp_Utility.Interfaces;
using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for handling file comparison operations.
    /// </summary>
    public class FileComparisonService : IFileComparisonService
    {
        /// <inheritdoc />
        public async Task<string> CompareFolderAsync(string folderPath, IProgress<string>? progress = null)
        {
            var comparer = new DumpComparer(message => progress?.Report(message));
            var fileHashes = await comparer.ComputeFileHashesAsync(folderPath);
            var report = comparer.GenerateFolderCompareReport(fileHashes, folderPath);
            return report;
        }
    }
}