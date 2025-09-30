using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a contract for controlling the stager and its associated hooks.
    /// </summary>
    public interface IPlcStagerController
    {
        /// <summary>
        /// Installs the stager payload onto the PLC.
        /// </summary>
        /// <param name="stagerPayload">The stager payload to install.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task InstallStager(byte[] stagerPayload, CancellationToken cancellationToken = default);

        /// <summary>
        /// Writes data to the PLC via the stager.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task WriteViaStager(uint address, byte[] contents, CancellationToken cancellationToken = default);

        /// <summary>
        /// Installs an additional hook via the stager.
        /// </summary>
        /// <param name="targetAddress">The target address of the new hook.</param>
        /// <param name="payload">The payload of the new hook.</param>
        /// <param name="newHookNo">The new hook number.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task InstallAddHookViaStager(uint targetAddress, byte[] payload, int newHookNo, CancellationToken cancellationToken = default);
    }
}