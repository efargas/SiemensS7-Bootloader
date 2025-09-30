using System;
using System.Linq;

namespace S7.Net
{
    public static class ProtocolUtils
    {
        public static byte[] EncodePacket(byte[] contents)
        {
            if (contents.Length > PlcConstants.MAX_PACKET_SIZE)
            {
                throw new ArgumentException($"Packet contents too large. Max size is {PlcConstants.MAX_PACKET_SIZE} bytes.", nameof(contents));
            }

            var packet = new byte[contents.Length + 2];
            EncodePacket(contents, packet);
            return packet;
        }

        public static int EncodePacket(ReadOnlySpan<byte> contents, Span<byte> destination)
        {
            if (contents.Length > PlcConstants.MAX_PACKET_SIZE)
            {
                throw new ArgumentException($"Packet contents too large. Max size is {PlcConstants.MAX_PACKET_SIZE} bytes.", nameof(contents));
            }

            int requiredLength = contents.Length + 2;
            if (destination.Length < requiredLength)
            {
                throw new ArgumentException("Destination span is too small.", nameof(destination));
            }

            destination[0] = (byte)(contents.Length + 1);
            contents.CopyTo(destination.Slice(1));
            destination[requiredLength - 1] = CalculateChecksum(destination.Slice(0, requiredLength - 1));
            return requiredLength;
        }

        public static byte[] DecodePacket(byte[] packet)
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

            byte receivedChecksum = packet.Last();
            byte calculatedChecksum = CalculateChecksum(new ReadOnlySpan<byte>(packet, 0, packet.Length - 1));

            if (receivedChecksum != calculatedChecksum)
            {
                throw new ChecksumMismatchException();
            }

            var contents = new byte[lengthByte - 1];
            Array.Copy(packet, 1, contents, 0, contents.Length);
            return contents;
        }

        public static int DecodePacket(ReadOnlySpan<byte> packet, Span<byte> destination)
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

            int contentsLength = lengthByte - 1;
            if (destination.Length < contentsLength)
            {
                throw new ArgumentException("Destination span is too small.", nameof(destination));
            }

            byte receivedChecksum = packet[packet.Length - 1];
            byte calculatedChecksum = CalculateChecksum(packet.Slice(0, packet.Length - 1));

            if (receivedChecksum != calculatedChecksum)
            {
                throw new ChecksumMismatchException();
            }

            packet.Slice(1, contentsLength).CopyTo(destination);
            return contentsLength;
        }

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