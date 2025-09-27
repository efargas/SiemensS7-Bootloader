using S7.Core.Abstractions.Configuration;
using S7.Net.Interfaces;

namespace S7.Core.Abstractions.Factories
{
    /// <summary>
    /// Represents a factory for creating PLC clients.
    /// </summary>
    public interface IPlcClientFactory
    {
        /// <summary>
        /// Creates a new instance of a PLC client based on the provided configuration.
        /// </summary>
        /// <param name="config">The communication channel configuration.</param>
        /// <returns>An instance of <see cref="IPlcClient"/>.</returns>
        IPlcClient Create(CommunicationChannelConfig config);
    }
}