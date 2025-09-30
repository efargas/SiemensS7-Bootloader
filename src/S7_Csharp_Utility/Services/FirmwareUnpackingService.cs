using S7.Utils;
using S7_Csharp_Utility.Interfaces;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for handling firmware unpacking operations.
    /// </summary>
    public class FirmwareUnpackingService : IFirmwareUnpackingService
    {
        private readonly S7UpdateUnpacker _unpacker;

        public FirmwareUnpackingService()
        {
            _unpacker = new S7UpdateUnpacker();
        }

        /// <inheritdoc />
        public Task<List<FwRawEntry>> ParseMetadataAsync(string firmwarePath, CancellationToken cancellationToken = default)
        {
            return _unpacker.ParseMetadataAsync(firmwarePath, cancellationToken);
        }

        /// <inheritdoc />
        public Task UnpackAsync(string firmwarePath, string outputPath, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
        {
            return _unpacker.UnpackAsync(firmwarePath, outputPath, progress, cancellationToken);
        }
    }
}