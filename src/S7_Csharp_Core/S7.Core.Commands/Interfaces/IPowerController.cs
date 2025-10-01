using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands.Interfaces
{
    /// <summary>
    /// Interface for power controller operations.
    /// </summary>
    public interface IPowerController
    {
        /// <summary>
        /// Performs a power cycle operation.
        /// </summary>
        /// <param name="host">The Modbus host</param>
        /// <param name="port">The Modbus port</param>
        /// <param name="coil">The coil address</param>
        /// <param name="delaySeconds">The delay after power cycle</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A task representing the operation</returns>
        Task PowerCycleAsync(string host, int port, int coil, int delaySeconds, CancellationToken cancellationToken = default);
    }
}