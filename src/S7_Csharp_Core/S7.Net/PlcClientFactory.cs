using Microsoft.Extensions.Logging;
using S7.Net.Interfaces;
using System;

namespace S7.Net
{
    /// <summary>
    /// A factory for creating PlcClient instances.
    /// </summary>
    public class PlcClientFactory : IPlcClientFactory
    {
        private readonly ILogger<PlcClient> _plcClientLogger;
        private readonly ILogger<PlcProtocol> _plcProtocolLogger;

        /// <summary>
        /// Initializes a new instance of the <see cref="PlcClientFactory"/> class.
        /// </summary>
        /// <param name="plcClientLogger">The logger for the PlcClient.</param>
        /// <param name="plcProtocolLogger">The logger for the PlcProtocol.</param>
        public PlcClientFactory(ILogger<PlcClient> plcClientLogger, ILogger<PlcProtocol> plcProtocolLogger)
        {
            _plcClientLogger = plcClientLogger ?? throw new ArgumentNullException(nameof(plcClientLogger));
            _plcProtocolLogger = plcProtocolLogger ?? throw new ArgumentNullException(nameof(plcProtocolLogger));
        }

        /// <inheritdoc />
        public PlcClient Create(ICommunicationChannel channel)
        {
            return new PlcClient(channel, _plcClientLogger, _plcProtocolLogger);
        }
    }
}