using Microsoft.Extensions.Logging;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a factory for creating PlcClient instances.
    /// This allows for easier dependency injection and testing of components that use PlcClient.
    /// </summary>
    public interface IPlcClientFactory
    {
        /// <summary>
        /// Creates a new PlcClient instance for the given communication channel.
        /// </summary>
        /// <param name="channel">The communication channel to be used by the client.</param>
        /// <returns>A new instance of PlcClient.</returns>
        PlcClient Create(ICommunicationChannel channel);
    }
}