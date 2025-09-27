using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines the public interface for a PLC client.
    /// </summary>
    public interface IPlcClient : IDisposable
    {
        /// <summary>
        /// Performs a handshake with the PLC.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous handshake operation.</returns>
        Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Dumps memory from the PLC at the specified address and length.
        /// </summary>
        /// <param name="address">The memory address to start dumping from.</param>
        /// <param name="length">The number of bytes to dump.</param>
        /// <param name="dumpMemPayload">The memory dumper payload binary.</param>
        /// <param name="progress">Progress reporter for the dump operation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The dumped memory data.</returns>
        Task<byte[]> DumpMemoryAsync(uint address, uint length, byte[] dumpMemPayload, IProgress<long>? progress = null, CancellationToken cancellationToken = default);
    }
}