using System;
using System.Buffers;
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
            await Task.Delay(PlcConstants.SEND_PACKET_DELAY_MS, cancellationToken);

            var packetBuffer = ArrayPool<byte>.Shared.Rent(contents.Length + 2);
            try
            {
                var packetSpan = new Span<byte>(packetBuffer);
                var packetLength = ProtocolUtils.EncodePacket(contents, packetSpan);
                var packetToSend = packetSpan.Slice(0, packetLength);

                _logger.LogTrace("-> SEND: {Packet}", Convert.ToHexString(packetToSend));

                for (int i = 0; i < packetToSend.Length; i += step)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int bytesToSend = Math.Min(step, packetToSend.Length - i);
                    await _channel.WriteAsync(packetBuffer, i, bytesToSend, cancellationToken);
                    if (sleepMs > 0)
                    {
                        await Task.Delay(sleepMs, cancellationToken);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(packetBuffer);
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
            var lengthBuffer = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                await _channel.ReadAsync(lengthBuffer, 0, 1, cancellationToken);
                int bytesToRead = lengthBuffer[0];

                if (bytesToRead == 0) return Array.Empty<byte>();

                var fullPacketBuffer = ArrayPool<byte>.Shared.Rent(bytesToRead + 1);
                try
                {
                    fullPacketBuffer[0] = (byte)bytesToRead;

                    int bytesRead = 0;
                    while (bytesRead < bytesToRead)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        bytesRead += await _channel.ReadAsync(fullPacketBuffer, 1 + bytesRead, bytesToRead - bytesRead, cancellationToken);
                    }

                    var fullPacketSpan = new ReadOnlySpan<byte>(fullPacketBuffer, 0, bytesToRead + 1);
                    _logger.LogTrace("<- RECV: {Packet}", Convert.ToHexString(fullPacketSpan));

                    // The DecodePacket method will allocate the final byte[] for the caller.
                    // The large intermediate buffer is pooled.
                    return ProtocolUtils.DecodePacket(fullPacketSpan.ToArray());
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(fullPacketBuffer);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lengthBuffer);
            }
        }
    }
}