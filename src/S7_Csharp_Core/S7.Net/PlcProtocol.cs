using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using S7.Net.Interfaces;

namespace S7.Net
{
    /// <summary>
    /// Handles the low-level protocol for communicating with the PLC.
    /// </summary>
    public class PlcProtocol
    {
        private readonly ICommunicationChannel _channel;
        private readonly Action<string> _log;

        /// <summary>
        /// Initializes a new instance of the <see cref="PlcProtocol"/> class.
        /// </summary>
        /// <param name="channel">The communication channel to use.</param>
        /// <param name="logger">The logging action.</param>
        public PlcProtocol(ICommunicationChannel channel, Action<string> logger)
        {
            _channel = channel;
            _log = logger;
        }

        /// <summary>
        /// Calculates the checksum for a packet.
        /// </summary>
        /// <param name="packetData">The packet data.</param>
        /// <param name="offset">The offset to start calculating from.</param>
        /// <param name="length">The number of bytes to include in the calculation.</param>
        /// <returns>The calculated checksum.</returns>
        public async Task SendPacketAsync(byte[] contents, int step = 2, int sleepMs = 10, CancellationToken cancellationToken = default)
        {
            // This initial delay mirrors the Python client's SEND_REQ_SAFETY_SLEEP_AMT
            // and is critical for stability.
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);

            var packet = ProtocolUtils.EncodePacket(contents);

            _log($"-> SEND: {BitConverter.ToString(packet).Replace("-", "")}");

            // Send the packet in small chunks to avoid overflowing the PLC's UART buffer
            for (int i = 0; i < packet.Length; i += step)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int bytesToSend = Math.Min(step, packet.Length - i);
                await _channel.WriteAsync(packet, i, bytesToSend, cancellationToken).ConfigureAwait(false);
                if (sleepMs > 0)
                {
                    await Task.Delay(sleepMs, cancellationToken).ConfigureAwait(false);
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
        /// <param name="buffer">The buffer containing the data to write.</param>
        /// <param name="offset">The offset in the buffer to start writing from.</param>
        /// <param name="count">The number of bytes to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task RawWriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            await _channel.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads raw data from the communication channel.
        /// </summary>
        /// <param name="buffer">The buffer to read the data into.</param>
        /// <param name="offset">The offset in the buffer to start writing to.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of bytes read.</returns>
        public async Task<int> RawReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            return await _channel.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Receives a packet from the PLC.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The contents of the packet, or null if a checksum error occurred.</returns>
        public async Task<byte[]?> ReceivePacketAsync(CancellationToken cancellationToken = default)
        {
            var lengthByte = new byte[1];
            await _channel.ReadAsync(lengthByte, 0, 1, cancellationToken).ConfigureAwait(false);
            int bytesToRead = lengthByte[0];

            if (bytesToRead == 0) return Array.Empty<byte>();

            var fullPacket = new byte[bytesToRead + 1];
            fullPacket[0] = lengthByte[0];

            int bytesRead = 0;
            while (bytesRead < bytesToRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bytesRead += await _channel.ReadAsync(fullPacket, 1 + bytesRead, bytesToRead - bytesRead, cancellationToken).ConfigureAwait(false);
            }

            _log($"<- RECV: {BitConverter.ToString(fullPacket).Replace("-", "")}");

            return ProtocolUtils.DecodePacket(fullPacket);
        }
    }
}
