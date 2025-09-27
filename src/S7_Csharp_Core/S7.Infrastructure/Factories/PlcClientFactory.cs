using System;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Factories;
using S7.Net;
using S7.Net.Channels;
using S7.Net.Interfaces;

namespace S7.Infrastructure.Factories
{
    /// <summary>
    /// A factory for creating PLC clients.
    /// </summary>
    public class PlcClientFactory : IPlcClientFactory
    {
        private readonly ILoggerFactory _loggerFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="PlcClientFactory"/> class.
        /// </summary>
        /// <param name="loggerFactory">The logger factory to create loggers for the clients.</param>
        public PlcClientFactory(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        /// <summary>
        /// Creates a new instance of a PLC client based on the provided configuration.
        /// </summary>
        /// <param name="config">The communication channel configuration.</param>
        /// <returns>An instance of <see cref="IPlcClient"/>.</returns>
        public IPlcClient Create(CommunicationChannelConfig config)
        {
            ArgumentNullException.ThrowIfNull(config);

            ICommunicationChannel channel = config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new SerialChannel(config.SerialPort ?? "COM1", config.BaudRate),
                _ => throw new ArgumentException($"Unsupported communication mode: {config.Mode}", nameof(config.Mode))
            };

            var logger = _loggerFactory.CreateLogger<PlcClient>();
            Action<string> loggerAction = message => logger.LogDebug("{Message}", message);

            return new PlcClient(channel, loggerAction);
        }
    }
}