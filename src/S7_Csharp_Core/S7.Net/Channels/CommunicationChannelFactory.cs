using S7.Core.Commands;
using S7.Net.Interfaces;
using System;

namespace S7.Net.Channels
{
    /// <summary>
    /// A factory for creating communication channels.
    /// </summary>
    public class CommunicationChannelFactory : ICommunicationChannelFactory
    {
        /// <summary>
        /// Creates a communication channel based on the provided configuration.
        /// </summary>
        /// <param name="config">The configuration for the channel.</param>
        /// <returns>An instance of a communication channel.</returns>
        public ICommunicationChannel Create(CommunicationChannelConfig config)
        {
            return config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new SerialChannel(
                    config.SerialPort ?? throw new ArgumentException("Serial port is required for serial communication"),
                    config.BaudRate,
                    config.Parity,
                    config.StopBits,
                    config.FlowControl),
                _ => throw new ArgumentException($"Unsupported communication mode: {config.Mode}")
            };
        }
    }
}