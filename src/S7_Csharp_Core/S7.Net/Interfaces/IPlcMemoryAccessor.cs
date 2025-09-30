using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a contract for accessing and manipulating PLC memory.
    /// </summary>
    public interface IPlcMemoryAccessor
    {
        /// <summary>
        /// Writes data to the PLC's IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task WriteToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default);

        /// <summary>
        /// Dumps a specified region of memory from the PLC.
        /// </summary>
        /// <param name="address">The starting address of the memory dump.</param>
        /// <param name="length">The number of bytes to dump.</param>
        /// <param name="dumpMemPayload">The payload required for the memory dump operation.</param>
        /// <param name="progress">An optional progress reporter.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A byte array containing the dumped memory.</returns>
        Task<byte[]> DumpMemoryAsync(uint address, uint length, byte[] dumpMemPayload, IProgress<long> progress, CancellationToken cancellationToken = default);
    }
}