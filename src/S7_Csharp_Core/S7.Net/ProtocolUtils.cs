using System;
using System.Linq;

namespace S7.Net
{
    public static class ProtocolUtils
    {
        /// <summary>
        /// Encodes the packet contents into the destination span.
        /// </summary>
        /// <param name="contents">The raw data to encode.</param>
        /// <param name="destination">The buffer to write the encoded packet into. Must be at least contents.Length + 2.</param>
        /// <returns>The number of bytes written to the destination span.</returns>
        public static int EncodePacket(ReadOnlySpan<byte> contents, Span<byte> destination)
        {
            if (contents.Length > 254)
            {
                throw new ArgumentException("Packet contents too large. Max size is 254 bytes.", nameof(contents));
            }
            if (destination.Length < contents.Length + 2)
            {
                throw new ArgumentException("Destination span is too small.", nameof(destination));
            }

            var packetLength = contents.Length + 1;
            destination[0] = (byte)packetLength;
            contents.CopyTo(destination.Slice(1));

            var checksumSpan = destination.Slice(0, packetLength);
            destination[packetLength] = CalculateChecksum(checksumSpan);

            return packetLength + 1;
        }

        /// <summary>
        /// Decodes a packet from a span.
        /// </summary>
        /// <param name="packet">The span containing the full packet data (including length and checksum).</param>
        /// <returns>The decoded packet contents.</returns>
        public static byte[] DecodePacket(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 2)
            {
                throw new ArgumentException("Invalid packet length.", nameof(packet));
            }

            var lengthByte = packet[0];
            if (lengthByte != packet.Length - 1)
            {
                throw new ArgumentException("Packet length mismatch.", nameof(packet));
            }

            byte receivedChecksum = packet[packet.Length - 1];
            byte calculatedChecksum = CalculateChecksum(packet.Slice(0, packet.Length - 1));

            if (receivedChecksum != calculatedChecksum)
            {
                throw new ChecksumMismatchException(receivedChecksum, calculatedChecksum);
            }

            var contents = new byte[lengthByte - 1];
            packet.Slice(1, contents.Length).CopyTo(contents);
            return contents;
        }

        /// <summary>
        /// Calculates the checksum for a given span of packet data.
        /// </summary>
        private static byte CalculateChecksum(ReadOnlySpan<byte> packetData)
        {
            int sum = 0;
            for (int i = 0; i < packetData.Length; i++)
            {
                sum += packetData[i];
            }
            return (byte)-sum;
        }
    }
}