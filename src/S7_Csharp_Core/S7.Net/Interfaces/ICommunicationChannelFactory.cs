using S7.Core.Commands;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a factory for creating communication channels.
    /// </summary>
    public interface ICommunicationChannelFactory
    {
        /// <summary>
        /// Creates a communication channel based on the provided configuration.
        /// </summary>
        /// <param name="config">The configuration for the channel.</param>
        /// <returns>An instance of a communication channel.</returns>
        ICommunicationChannel Create(CommunicationChannelConfig config);
    }
}