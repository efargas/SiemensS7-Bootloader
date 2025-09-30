using S7.Utils;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for handling firmware unpacking operations.
    /// </summary>
    public interface IFirmwareUnpackingService
    {
        /// <summary>
        /// Parses the metadata from a firmware file.
        /// </summary>
        /// <param name="firmwarePath">The path to the firmware file.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A list of firmware entries found in the file.</returns>
        Task<List<FwRawEntry>> ParseMetadataAsync(string firmwarePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Unpacks a firmware file to a specified output path.
        /// </summary>
        /// <param name="firmwarePath">The path to the firmware file.</param>
        /// <param name="outputPath">The path to write the unpacked file to.</param>
        /// <param name="progress">An optional progress reporter.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task UnpackAsync(string firmwarePath, string outputPath, IProgress<double>? progress = null, CancellationToken cancellationToken = default);
    }
}