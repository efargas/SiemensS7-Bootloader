using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils;

namespace S7.Net
{
    /// <summary>
    /// Helper class for calculating PL011 UART baud rate divisors.
    /// </summary>
    public static class UartBaudRateCalculator
    {
        /// <summary>
        /// Default UART clock frequency for Siemens S7-1200 PLC (14.7456 MHz).
        /// This value can be overridden if needed for different hardware variants.
        /// </summary>
        public const uint DefaultUartClockHz = 14745600;

        /// <summary>
        /// Calculates the integer and fractional baud rate divisors for PL011 UART.
        /// </summary>
        /// <param name="baudRate">Target baud rate (e.g., 115200)</param>
        /// <param name="uartClockHz">UART clock frequency in Hz (default: 14745600)</param>
        /// <returns>Tuple containing (IBRD, FBRD) divisors</returns>
        /// <exception cref="ArgumentException">Thrown when baud rate is invalid</exception>
        public static (uint ibrd, uint fbrd) CalculateDivisors(uint baudRate, uint uartClockHz = DefaultUartClockHz)
        {
            if (baudRate == 0)
                throw new ArgumentException("Baud rate must be greater than zero", nameof(baudRate));
            
            if (uartClockHz == 0)
                throw new ArgumentException("UART clock frequency must be greater than zero", nameof(uartClockHz));

            // BaudRateDivisor = UARTCLK / (16 × BaudRate)
            double baudRateDivisor = (double)uartClockHz / (16.0 * baudRate);
            
            // IBRD = integer part of divisor
            uint ibrd = (uint)baudRateDivisor;
            
            // FBRD = integer((fractional part) × 64 + 0.5)
            double fractionalPart = baudRateDivisor - ibrd;
            uint fbrd = (uint)(fractionalPart * 64.0 + 0.5);
            
            // Validate divisors
            if (ibrd == 0 || ibrd > 65535)
                throw new ArgumentException($"Calculated IBRD ({ibrd}) is out of valid range (1-65535) for baud rate {baudRate}", nameof(baudRate));
            
            if (fbrd > 63)
                fbrd = 63; // Cap at maximum value
            
            return (ibrd, fbrd);
        }

        /// <summary>
        /// Gets pre-calculated divisors for common baud rates.
        /// These are optimized for the default UART clock of 14.7456 MHz.
        /// </summary>
        public static (uint ibrd, uint fbrd) GetCommonBaudRateDivisors(uint baudRate)
        {
            return baudRate switch
            {
                38400 => (24, 0),
                57600 => (16, 0),
                115200 => (8, 0),
                230400 => (4, 0),
                460800 => (2, 0),
                _ => CalculateDivisors(baudRate) // Fallback to calculation
            };
        }
    }

    /// <summary>
    /// Manages memory operations for Siemens S7 PLC communication.
    /// Responsible for IRAM writes, subprotocol operations, and memory dumps.
    /// </summary>
    public sealed class PlcMemoryManager
    {
        private readonly PlcProtocolHandler _protocolHandler;
        private readonly Action<string> _log;
        private uint _nextPayloadLocation = PlcConstants.DUMPER_PAYLOAD_LOCATION;

        /// <summary>
        /// Initializes a new instance of the PlcMemoryManager class.
        /// </summary>
        /// <param name="protocolHandler">The protocol handler to use for communication.</param>
        /// <param name="logger">The logger action.</param>
        /// <exception cref="ArgumentNullException">Thrown when protocolHandler or logger is null.</exception>
        public PlcMemoryManager(PlcProtocolHandler protocolHandler, Action<string> logger)
        {
            _protocolHandler = protocolHandler ?? throw new ArgumentNullException(nameof(protocolHandler));
            _log = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets the next available payload location in memory.
        /// </summary>
        public uint NextPayloadLocation => _nextPayloadLocation;

        /// <summary>
        /// Advances the next payload location by the specified size and aligns to 4-byte boundary.
        /// </summary>
        /// <param name="size">The size to advance by.</param>
        public void AdvancePayloadLocation(uint size)
        {
            _nextPayloadLocation += size;
            // Align to next 4-byte boundary
            if (_nextPayloadLocation % 4 != 0)
            {
                _nextPayloadLocation = _nextPayloadLocation - (_nextPayloadLocation % 4) + 4;
            }
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
        /// Enters a subprotocol mode.
        /// </summary>
        /// <param name="mode">The mode to enter.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task EnterSubprotocolAsync(int mode, CancellationToken cancellationToken = default)
        {
            _log($"Entering subprotocol mode {mode}...");
            ushort magic = PlcConstants.SUBPROT_80_MODE_MAGICS[mode];
            byte[] payload = BitConverter.GetBytes(magic);
            if (BitConverter.IsLittleEndian) Array.Reverse(payload); // Make big-endian
            var response = await _protocolHandler.InvokePrimaryHandlerAsync(0x80, payload, true, cancellationToken).ConfigureAwait(false);
            if (response == null || !response.SequenceEqual(PlcConstants.ANSW_ENTER_SUBPROTO_SUCCESS))
                throw new Exception("Failed to enter subprotocol.");
            _log("Entered subprotocol successfully.");
        }

        /// <summary>
        /// Leaves the current subprotocol mode.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task LeaveSubprotocolAsync(CancellationToken cancellationToken = default)
        {
            _log("Leaving subprotocol...");
            await _protocolHandler.SendPacketAsync(new byte[] { 0x81, 0xD0, 0x67 }, cancellationToken: cancellationToken).ConfigureAwait(false);
            try
            {
                await _protocolHandler.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log($"[WARNING] Error while leaving subprotocol: {ex.Message}");
            }
        }

        /// <summary>
        /// Writes data to the PLC in subprotocol mode.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="data">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task RawSubprotocolWriteAsync(uint address, byte[] data, CancellationToken cancellationToken = default)
        {
            var payload = new byte[7 + data.Length];
            payload[0] = 0x84;
            payload[1] = 0x5a;
            payload[2] = 0x2e;
            var addrBytes = GetBigEndianBytes(address);
            Array.Copy(addrBytes, 0, payload, 3, 4);
            Array.Copy(data, 0, payload, 7, data.Length);

            await _protocolHandler.SendPacketAsync(payload, cancellationToken: cancellationToken).ConfigureAwait(false);
            try
            {
                await _protocolHandler.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log($"[WARNING] Error in response to RawSubprotocolWrite: {ex.Message}");
            }
        }

        /// <summary>
        /// Writes a chunk of data to IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task WriteChunkToIramAsync(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            uint targetArgument = targetAddress - 0x10000000;
            // 1. Mask with 0xFF bytes
            await RawSubprotocolWriteAsync(targetArgument, Enumerable.Repeat((byte)0xFF, contents.Length).ToArray(), cancellationToken).ConfigureAwait(false);
            // 2. Write actual contents
            await RawSubprotocolWriteAsync(targetArgument, contents, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes data to IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteToIramAsync(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            _log($"Writing {contents.Length} bytes to IRAM at 0x{targetAddress:X8}");
            await EnterSubprotocolAsync(PlcConstants.SUBPROT_80_MODE_IRAM, cancellationToken).ConfigureAwait(false);

            int chunkSize = 16; // From python script
            for (int i = 0; i < contents.Length; i += chunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int size = Math.Min(chunkSize, contents.Length - i);
                var chunk = new byte[size];
                Array.Copy(contents, i, chunk, 0, size);
                _log($"Writing chunk {i / chunkSize + 1}...");
                await WriteChunkToIramAsync(targetAddress + (uint)i, chunk, cancellationToken).ConfigureAwait(false);
            }

            await LeaveSubprotocolAsync(cancellationToken).ConfigureAwait(false);
            _log("Finished writing to IRAM.");
        }

        /// <summary>
        /// Receives a large amount of data from the PLC.
        /// </summary>
        /// <param name="progress">The progress reporter.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The received data.</returns>
        public async Task<byte[]> ReceiveManyAsync(IProgress<long>? progress, CancellationToken cancellationToken = default)
        {
            using var ms = new MemoryStream();
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var chunk = await _protocolHandler.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
                if (chunk == null || chunk.Length == 0)
                {
                    break;
                }
                await ms.WriteAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
                progress?.Report(ms.Length);
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Dumps memory from the PLC at the specified address and length.
        /// </summary>
        /// <param name="address">The memory address to start dumping from.</param>
        /// <param name="length">The number of bytes to dump.</param>
        /// <param name="dumpMemPayload">The memory dumper payload binary.</param>
        /// <param name="stagerManager">The stager manager for payload installation.</param>
        /// <param name="progress">Progress reporter for the dump operation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The dumped memory data.</returns>
        /// <exception cref="InvalidOperationException">Thrown when not connected to PLC.</exception>
        /// <exception cref="ArgumentNullException">Thrown when dumpMemPayload is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
        public async Task<byte[]> DumpMemoryAsync(uint address, uint length, byte[] dumpMemPayload, PlcStagerManager stagerManager, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
        {
            if (dumpMemPayload is null) throw new ArgumentNullException(nameof(dumpMemPayload));
            if (stagerManager is null) throw new ArgumentNullException(nameof(stagerManager));
            if (length == 0) throw new ArgumentException("Length must be greater than zero.", nameof(length));
            if (dumpMemPayload.Length == 0) throw new ArgumentException("Dump memory payload cannot be empty.", nameof(dumpMemPayload));
            
            // Validate reasonable memory dump size (prevent excessive memory usage)
            if (length > Constants.BufferSizes.MaxMemoryDumpSize)
                throw new ArgumentException($"Dump size too large. Maximum allowed is {Constants.BufferSizes.MaxMemoryDumpSize:N0} bytes, requested {length:N0} bytes.", nameof(length));

            cancellationToken.ThrowIfCancellationRequested();

            _log("Installing memory dumper payload...");
            await stagerManager.InstallAddHookViaStagerAsync(_nextPayloadLocation, dumpMemPayload, PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, cancellationToken).ConfigureAwait(false);
            AdvancePayloadLocation((uint)dumpMemPayload.Length);
            _log("Memory dumper payload installed.");

            cancellationToken.ThrowIfCancellationRequested();

            _log($"Requesting memory dump of {length} bytes from 0x{address:X8}...");
            // Prepare arguments: "A" + address + length
            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            var addrBytes = GetBigEndianBytes(address);
            var lenBytes = GetBigEndianBytes(length);
            Array.Copy(addrBytes, 0, args, 1, 4);
            Array.Copy(lenBytes, 0, args, 5, 4);

            var response = await _protocolHandler.InvokeAddHookAsync(PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, args, true, cancellationToken).ConfigureAwait(false);

            if (response == null || !System.Text.Encoding.ASCII.GetString(response).TrimEnd('\0').StartsWith("Ok"))
            {
                var responseStr = response != null ? BitConverter.ToString(response) : "<null>";
                throw new Exception($"Failed to start memory dump. Unexpected response: {responseStr}");
            }

            cancellationToken.ThrowIfCancellationRequested();

            _log("Memory dump started. Receiving data...");
            var data = await ReceiveManyAsync(progress, cancellationToken).ConfigureAwait(false);
            _log($"Memory dump complete. Received {data.Length} bytes.");
            return data;
        }

        /// <summary>
        /// Sets the UART speed on the PLC by uploading and executing the UART speed reconfiguration payload.
        /// </summary>
        /// <param name="baudRate">The target baud rate (38400, 57600, 115200, 230400, or 460800).</param>
        /// <param name="uartSpeedPayload">The UART speed reconfiguration payload.</param>
        /// <param name="stagerManager">The stager manager for payload installation.</param>
        /// <param name="uartClockHz">UART clock frequency in Hz (default: 14745600 for S7-1200). Override for different hardware.</param>
        /// <param name="onSuccessCallback">Optional callback invoked after successful PLC reconfiguration, before host reconfiguration is needed. Receives the new baud rate as parameter.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if UART speed was successfully changed, false otherwise.</returns>
        /// <exception cref="InvalidOperationException">Thrown when not connected to PLC.</exception>
        /// <exception cref="ArgumentNullException">Thrown when uartSpeedPayload is null.</exception>
        /// <exception cref="ArgumentException">Thrown when baud rate is invalid.</exception>
        public async Task<bool> SetUartSpeedAsync(uint baudRate, byte[] uartSpeedPayload, PlcStagerManager stagerManager, uint uartClockHz = UartBaudRateCalculator.DefaultUartClockHz, Action<uint>? onSuccessCallback = null, CancellationToken cancellationToken = default)
        {
            if (uartSpeedPayload is null) throw new ArgumentNullException(nameof(uartSpeedPayload));
            if (stagerManager is null) throw new ArgumentNullException(nameof(stagerManager));
            if (uartSpeedPayload.Length == 0) throw new ArgumentException("UART speed payload cannot be empty.", nameof(uartSpeedPayload));
            
            if (baudRate == 0)
                throw new ArgumentException("Baud rate must be greater than zero.", nameof(baudRate));

            cancellationToken.ThrowIfCancellationRequested();

            // Calculate baud rate divisors based on UART clock frequency
            _log($"Calculating UART divisors for {baudRate} baud (UART clock: {uartClockHz} Hz)...");
            var (ibrd, fbrd) = UartBaudRateCalculator.CalculateDivisors(baudRate, uartClockHz);
            _log($"Calculated divisors: IBRD={ibrd}, FBRD={fbrd}");

            _log($"Installing UART speed reconfiguration payload (target: {baudRate} baud)...");
            await stagerManager.InstallAddHookViaStagerAsync(_nextPayloadLocation, uartSpeedPayload, PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, cancellationToken).ConfigureAwait(false);
            AdvancePayloadLocation((uint)uartSpeedPayload.Length);
            _log("UART speed payload installed.");

            cancellationToken.ThrowIfCancellationRequested();

            _log($"Requesting UART speed change to {baudRate} baud (IBRD={ibrd}, FBRD={fbrd})...");
            // Prepare arguments: "A" + IBRD (4 bytes) + FBRD (4 bytes)
            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            var ibrdBytes = GetBigEndianBytes(ibrd);
            var fbrdBytes = GetBigEndianBytes(fbrd);
            Buffer.BlockCopy(ibrdBytes, 0, args, 1, 4);
            Buffer.BlockCopy(fbrdBytes, 0, args, 5, 4);

            var response = await _protocolHandler.InvokeAddHookAsync(PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND, args, true, cancellationToken).ConfigureAwait(false);

            if (response == null)
            {
                _log("[WARNING] No response from UART speed payload.");
                return false;
            }

            var responseStr = System.Text.Encoding.ASCII.GetString(response).TrimEnd('\0');
            _log($"UART speed payload response: {responseStr}");

            if (responseStr.StartsWith("UART_SPEED_OK"))
            {
                _log($"✅ UART speed successfully changed to {baudRate} baud.");
                
                // Invoke callback before host reconfiguration (e.g., to restart socat)
                if (onSuccessCallback != null)
                {
                    _log($"Invoking success callback for host reconfiguration...");
                    try
                    {
                        onSuccessCallback(baudRate);
                        _log($"✅ Host reconfiguration callback completed successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log($"⚠️  Warning: Host reconfiguration callback failed: {ex.Message}");
                        _log($"⚠️  You must manually reconfigure your socat/serial connection to {baudRate} baud!");
                    }
                }
                else
                {
                    _log($"⚠️  WARNING: You must now reconfigure your socat/serial connection to {baudRate} baud!");
                }
                
                return true;
            }
            else if (responseStr.StartsWith("UART_SPEED_ERR"))
            {
                _log($"❌ UART speed change failed. PLC reported error.");
                return false;
            }
            else
            {
                _log($"⚠️  Unexpected response from UART speed payload: {responseStr}");
                return false;
            }
        }
    }
}