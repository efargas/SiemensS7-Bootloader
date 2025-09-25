using System;
using System.Buffers;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using S7.Net.Interfaces;
using S7.Utils;

namespace S7.Net
{
    /// <summary>
    /// Handles low-level protocol operations for Siemens S7 PLC communication.
    /// Responsible for handshake, version retrieval, and basic protocol operations.
    /// </summary>
    public sealed class PlcProtocolHandler
    {
        private readonly ICommunicationChannel _channel;
        private readonly PlcProtocol _protocol;
        private readonly Action<string> _log;

        /// <summary>
        /// Initializes a new instance of the PlcProtocolHandler class.
        /// </summary>
        /// <param name="channel">The communication channel to use.</param>
        /// <param name="logger">The logger action.</param>
        /// <exception cref="ArgumentNullException">Thrown when channel or logger is null.</exception>
        public PlcProtocolHandler(ICommunicationChannel channel, Action<string> logger)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _protocol = new PlcProtocol(channel, logger ?? throw new ArgumentNullException(nameof(logger)));
            _log = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Indicates whether the client is connected to the PLC.
        /// </summary>
        public bool IsConnected => _channel.IsConnected;

        /// <summary>
        /// Invokes a primary handler on the PLC.
        /// </summary>
        /// <param name="handlerIndex">The index of the handler to invoke.</param>
        /// <param name="args">The arguments to pass to the handler.</param>
        /// <param name="awaitResponse">Whether to wait for a response.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The response from the PLC, or null if no response was awaited.</returns>
        /// <exception cref="InvalidOperationException">Thrown when not connected to PLC.</exception>
        /// <exception cref="ArgumentNullException">Thrown when args is null.</exception>
        /// <exception cref="ArgumentException">Thrown when args is too large for protocol.</exception>
        public async Task<byte[]?> InvokePrimaryHandlerAsync(byte handlerIndex, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            if (args is null) throw new ArgumentNullException(nameof(args));
            
            // Validate payload size doesn't exceed protocol limits
            if (args.Length > Constants.Protocol.MaxPayloadSize - 1)
                throw new ArgumentException($"Arguments too large. Maximum size is {Constants.Protocol.MaxPayloadSize - 1} bytes, got {args.Length} bytes.", nameof(args));

            var payload = new byte[1 + args.Length];
            payload[0] = handlerIndex;
            Array.Copy(args, 0, payload, 1, args.Length);
            await _protocol.SendPacketAsync(payload, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!awaitResponse) return null;
            try
            {
                return await _protocol.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch in response to handler 0x{handlerIndex:X2}: {ex.Message}");
                return null;
            }
        }

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
                await _protocol.RawWriteAsync(handshakePayload, 0, handshakePayload.Length, cancellationToken).ConfigureAwait(false);
                var sw = Stopwatch.StartNew();
                var responseBuffer = new System.Collections.Generic.List<byte>();
                while (sw.ElapsedMilliseconds < 300)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (_protocol.DataAvailable)
                    {
                        // Use ArrayPool for temporary buffer to reduce allocations
                        var tmpBuf = ArrayPool<byte>.Shared.Rent(Constants.BufferSizes.TempBuffer);
                        try
                        {
                            int bytesRead = await _protocol.RawReadAsync(tmpBuf, 0, Constants.BufferSizes.TempBuffer, cancellationToken).ConfigureAwait(false);
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
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(tmpBuf);
                        }
                    }
                    await Task.Delay(50, cancellationToken).ConfigureAwait(false);
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
                await Task.Delay(10, cancellationToken).ConfigureAwait(false); // brief pause before retry
            }
            _log("Handshake failed.");
            return false;
        }

        /// <summary>
        /// Gets the version of the PLC bootloader.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The version string.</returns>
        public async Task<string> GetVersionAsync(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            _log("Getting bootloader version...");
            var response = await InvokePrimaryHandlerAsync(0, Array.Empty<byte>(), true, cancellationToken).ConfigureAwait(false);
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
        /// Invokes an additional hook on the PLC.
        /// </summary>
        /// <param name="hookNo">The hook number to invoke.</param>
        /// <param name="args">The arguments to pass to the hook.</param>
        /// <param name="awaitResponse">Whether to wait for a response.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The response from the PLC, or null if no response was awaited.</returns>
        public async Task<byte[]?> InvokeAddHookAsync(int hookNo, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            if (hookNo < 0 || hookNo > 0x20)
                throw new ArgumentOutOfRangeException(nameof(hookNo));

            var payload = new byte[1 + args.Length];
            payload[0] = (byte)hookNo;
            Array.Copy(args, 0, payload, 1, args.Length);

            return await InvokePrimaryHandlerAsync(0x1c, payload, awaitResponse, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Receives a packet from the PLC protocol.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The received packet data.</returns>
        public async Task<byte[]?> ReceivePacketAsync(CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            try
            {
                return await _protocol.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChecksumMismatchException ex)
            {
                _log($"[ERROR] Checksum mismatch during packet receive: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Sends a packet via the PLC protocol.
        /// </summary>
        /// <param name="payload">The payload to send.</param>
        /// <param name="step">The step size for transmission.</param>
        /// <param name="sleepMs">The sleep time between steps in milliseconds.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task SendPacketAsync(byte[] payload, int step = 0, int sleepMs = 0, CancellationToken cancellationToken = default)
        {
            if (_protocol is null) throw new InvalidOperationException("Not connected.");
            await _protocol.SendPacketAsync(payload, step, sleepMs, cancellationToken).ConfigureAwait(false);
        }
    }
}