using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a contract for managing the handshake process with a PLC.
    /// </summary>
    public interface IPlcHandshakeManager
    {
        /// <summary>
        /// Performs the initial handshake to gain special access to the PLC.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>True if the handshake was successful; otherwise, false.</returns>
        Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken = default);
    }
}