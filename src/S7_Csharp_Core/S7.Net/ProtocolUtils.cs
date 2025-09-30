using System;
using System.Linq;

namespace S7.Net
{
    public static class ProtocolUtils
    {
        public static byte[] EncodePacket(byte[] contents)
        {
            if (contents.Length > 254)
            {
                throw new ArgumentException("Packet contents too large. Max size is 254 bytes.", nameof(contents));
            }

            var packet = new byte[contents.Length + 2];
            packet[0] = (byte)(contents.Length + 1);
            Array.Copy(contents, 0, packet, 1, contents.Length);
            packet[packet.Length - 1] = CalculateChecksum(packet, 0, packet.Length - 1);
            return packet;
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
            byte calculatedChecksum = CalculateChecksum(packet, 0, packet.Length - 1);

            if (receivedChecksum != calculatedChecksum)
            {
                throw new ChecksumMismatchException();
            }

            var contents = new byte[lengthByte - 1];
            Array.Copy(packet, 1, contents, 0, contents.Length);
            return contents;
        }

        private static byte CalculateChecksum(byte[] packetData, int offset, int length)
        {
            int sum = 0;
            for (int i = 0; i < length; i++)
            {
                sum += packetData[offset + i];
            }
            return (byte)-sum;
        }
    }
}