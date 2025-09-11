using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net
{
    public class PlcProtocol
    {
        private readonly NetworkStream _stream;
        private readonly Action<string> _log;

        public PlcProtocol(NetworkStream stream, Action<string> logger)
        {
            _stream = stream;
            _log = logger;
        }

        private byte CalculateChecksum(byte[] packetData, int offset, int length)
        {
            int sum = 0;
            for (int i = 0; i < length; i++)
            {
                sum += packetData[offset + i];
            }
            return (byte)-sum;
        }

        public async Task SendPacketAsync(byte[] contents, int step = 2, int sleepMs = 10)
        {
            if (contents.Length > PlcConstants.MAX_MSG_LEN)
                throw new ArgumentException($"Message too long. Max length is {PlcConstants.MAX_MSG_LEN} bytes.");

            var packet = new byte[contents.Length + 2];
            packet[0] = (byte)(contents.Length + 1);
            Array.Copy(contents, 0, packet, 1, contents.Length);
            packet[packet.Length - 1] = CalculateChecksum(packet, 0, packet.Length - 1);

            _log($"-> SEND: {BitConverter.ToString(packet).Replace("-", "")}");

            for (int i = 0; i < packet.Length; i += step)
            {
                int bytesToSend = Math.Min(step, packet.Length - i);
                await _stream.WriteAsync(packet, i, bytesToSend);
                if (sleepMs > 0) await Task.Delay(sleepMs);
            }
        }

        public bool DataAvailable => _stream.DataAvailable;

        public async Task RawWriteAsync(byte[] buffer, int offset, int count)
        {
            await _stream.WriteAsync(buffer, offset, count);
        }

        public async Task<int> RawReadAsync(byte[] buffer, int offset, int count)
        {
            return await _stream.ReadAsync(buffer, offset, count);
        }

        public async Task<byte[]?> ReceivePacketAsync(int timeoutMs = 2000)
        {
            var cancellationTokenSource = new CancellationTokenSource(timeoutMs);
            var token = cancellationTokenSource.Token;

            var lengthByte = new byte[1];
            await _stream.ReadAsync(lengthByte, 0, 1, token);
            int bytesToRead = lengthByte[0];

            if (bytesToRead == 0) return Array.Empty<byte>();

            var fullPacket = new byte[bytesToRead + 1];
            fullPacket[0] = lengthByte[0];

            int bytesRead = 0;
            while(bytesRead < bytesToRead)
            {
                bytesRead += await _stream.ReadAsync(fullPacket, 1 + bytesRead, bytesToRead - bytesRead, token);
            }

            _log($"<- RECV: {BitConverter.ToString(fullPacket).Replace("-", "")}");

            byte receivedChecksum = fullPacket.Last();
            byte calculatedChecksum = CalculateChecksum(fullPacket, 0, fullPacket.Length - 1);

            if (receivedChecksum != calculatedChecksum)
            {
                _log("CHECKSUM ERROR!");
                return null;
            }

            var contents = new byte[bytesToRead - 1];
            Array.Copy(fullPacket, 1, contents, 0, contents.Length);
            return contents;
        }
    }
}
