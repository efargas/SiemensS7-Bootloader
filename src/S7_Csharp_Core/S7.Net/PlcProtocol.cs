using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Net.Interfaces;

namespace S7.Net
{
    /// <summary>
    /// Handles the low-level protocol for communicating with the PLC.
    /// </summary>
    public class PlcProtocol
    {
        private readonly ICommunicationChannel _channel;
        private readonly ILogger<PlcProtocol> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="PlcProtocol"/> class.
        /// </summary>
        /// <param name="channel">The communication channel to use.</param>
        /// <param name="logger">The logger instance.</param>
        public PlcProtocol(ICommunicationChannel channel, ILogger<PlcProtocol> logger)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Sends a packet to the PLC.
        /// </summary>
        public async Task SendPacketAsync(byte[] contents, int step = 2, int sleepMs = 10, CancellationToken cancellationToken = default)
        {
            await Task.Delay(10, cancellationToken);

            var packet = ProtocolUtils.EncodePacket(contents);

            _logger.LogTrace("-> SEND: {Packet}", BitConverter.ToString(packet).Replace("-", ""));

            for (int i = 0; i < packet.Length; i += step)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int bytesToSend = Math.Min(step, packet.Length - i);
                await _channel.WriteAsync(packet, i, bytesToSend, cancellationToken);
                if (sleepMs > 0)
                {
                    await Task.Delay(sleepMs, cancellationToken);
                }
            }
        }

        /// <summary>
        /// Indicates whether there is data available to be read from the communication channel.
        /// </summary>
        public bool DataAvailable => _channel.DataAvailable;

        /// <summary>
        /// Writes raw data to the communication channel.
        /// </summary>
        public async Task RawWriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            await _channel.WriteAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Reads raw data from the communication channel.
        /// </summary>
        public async Task<int> RawReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            return await _channel.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Receives a packet from the PLC.
        /// </summary>
        public async Task<byte[]?> ReceivePacketAsync(CancellationToken cancellationToken = default)
        {
            var lengthByte = new byte[1];
            await _channel.ReadAsync(lengthByte, 0, 1, cancellationToken);
            int bytesToRead = lengthByte[0];

            if (bytesToRead == 0) return Array.Empty<byte>();

            var fullPacket = new byte[bytesToRead + 1];
            fullPacket[0] = lengthByte[0];

            int bytesRead = 0;
            while (bytesRead < bytesToRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bytesRead += await _channel.ReadAsync(fullPacket, 1 + bytesRead, bytesToRead - bytesRead, cancellationToken);
            }

            _logger.LogTrace("<- RECV: {Packet}", BitConverter.ToString(fullPacket).Replace("-", ""));

            return ProtocolUtils.DecodePacket(fullPacket);
        }
    }
}