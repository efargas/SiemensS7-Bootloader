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
        private byte CalculateChecksum(byte[] packetData, int offset, int length)
        {
            int sum = 0;
            for (int i = 0; i < length; i++)
            {
                sum += packetData[offset + i];
            }
            return (byte)-sum;
        }

        /// <summary>
        /// Sends a packet to the PLC.
        /// </summary>
        /// <param name="contents">The contents of the packet.</param>
        /// <param name="step">The number of bytes to send at a time.</param>
        /// <param name="sleepMs">The number of milliseconds to sleep between steps.</param>
        // The default values for step (2) and sleepMs (10) are based on the Python
        // client's `send_packet` function, which uses a step of 2 and a sleep_amt of 0.01s.
        public async Task SendPacketAsync(byte[] contents, int step = 2, int sleepMs = 10, CancellationToken cancellationToken = default)
        {
            // This initial delay mirrors the Python client's SEND_REQ_SAFETY_SLEEP_AMT
            // and is critical for stability.
            await Task.Delay(10, cancellationToken);

            if (contents.Length > PlcConstants.MAX_MSG_LEN)
            {
                throw new ArgumentException($"Packet contents too large. Max size is {PlcConstants.MAX_MSG_LEN} bytes.", nameof(contents));
            }

            var packet = new byte[contents.Length + 2];
            packet[0] = (byte)(contents.Length + 1);
            Array.Copy(contents, 0, packet, 1, contents.Length);
            packet[packet.Length - 1] = CalculateChecksum(packet, 0, packet.Length - 1);

            _log($"-> SEND: {BitConverter.ToString(packet).Replace("-", "")}");

            // Send the packet in small chunks to avoid overflowing the PLC's UART buffer
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
        /// <param name="buffer">The buffer containing the data to write.</param>
        /// <param name="offset">The offset in the buffer to start writing from.</param>
        /// <param name="count">The number of bytes to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task RawWriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            await _channel.WriteAsync(buffer, offset, count, cancellationToken);
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
            return await _channel.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Receives a packet from the PLC.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The contents of the packet, or null if a checksum error occurred.</returns>
        public async Task<byte[]?> ReceivePacketAsync(CancellationToken cancellationToken = default)
        {
            var lengthByte = new byte[1];
            await _channel.ReadAsync(lengthByte, 0, 1, cancellationToken);
            int bytesToRead = lengthByte[0];

            if (bytesToRead == 0) return Array.Empty<byte>();

            var fullPacket = new byte[bytesToRead + 1];
            fullPacket[0] = lengthByte[0];

            int bytesRead = 0;
            while(bytesRead < bytesToRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bytesRead += await _channel.ReadAsync(fullPacket, 1 + bytesRead, bytesToRead - bytesRead, cancellationToken);
            }

            _log($"<- RECV: {BitConverter.ToString(fullPacket).Replace("-", "")}");

            byte receivedChecksum = fullPacket.Last();
            byte calculatedChecksum = CalculateChecksum(fullPacket, 0, fullPacket.Length - 1);

            if (receivedChecksum != calculatedChecksum)
            {
                _log("CHECKSUM ERROR!");
                throw new ChecksumMismatchException();
            }

            var contents = new byte[bytesToRead - 1];
            Array.Copy(fullPacket, 1, contents, 0, contents.Length);
            return contents;
        }
    }
}
