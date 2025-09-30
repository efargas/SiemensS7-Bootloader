using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a contract for retrieving information from a PLC.
    /// </summary>
    public interface IPlcInformationProvider
    {
        /// <summary>
        /// Gets the version of the PLC bootloader.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The version string.</returns>
        Task<string> GetVersion(CancellationToken cancellationToken = default);
    }
}