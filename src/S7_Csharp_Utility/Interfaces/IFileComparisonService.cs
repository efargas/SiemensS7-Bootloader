using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for handling file comparison operations.
    /// </summary>
    public interface IFileComparisonService
    {
        /// <summary>
        /// Compares all files in a given folder by hashing them and generates a report.
        /// </summary>
        /// <param name="folderPath">The path to the folder to analyze.</param>
        /// <param name="progress">An optional progress reporter for status updates.</param>
        /// <returns>A string containing the detailed comparison report.</returns>
        Task<string> CompareFolderAsync(string folderPath, IProgress<string>? progress = null);
    }
}