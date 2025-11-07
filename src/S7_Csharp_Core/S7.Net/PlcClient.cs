using System;
using S7.Net.Interfaces;
using System.Threading.Tasks;
using System.Threading;
using S7.Utils;

namespace S7.Net
{
    /// <summary>
    /// The main client for communicating with Siemens S7 PLCs using the undocumented bootloader protocol.
    /// Coordinates between protocol handler, memory manager, and stager manager components.
    /// </summary>
    public sealed class PlcClient : IDisposable
    {
        private readonly ICommunicationChannel _channel;
        private readonly PlcProtocolHandler _protocolHandler;
        private readonly PlcMemoryManager _memoryManager;
        private readonly PlcStagerManager _stagerManager;
        private readonly Action<string> _log;

        /// <summary>
        /// Initializes a new instance of the PlcClient class.
        /// </summary>
        /// <param name="channel">The communication channel to use.</param>
        /// <param name="logger">The logger action.</param>
        /// <exception cref="ArgumentNullException">Thrown when channel or logger is null.</exception>
        public PlcClient(ICommunicationChannel channel, Action<string> logger)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _log = logger ?? throw new ArgumentNullException(nameof(logger));
            
            // Initialize components with proper dependency injection
            _protocolHandler = new PlcProtocolHandler(channel, logger);
            _memoryManager = new PlcMemoryManager(_protocolHandler, logger);
            _stagerManager = new PlcStagerManager(_protocolHandler, _memoryManager, logger);
        }

        /// <summary>
        /// Indicates whether the client is connected to the PLC.
        /// </summary>
        public bool IsConnected => _protocolHandler.IsConnected;

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
        public async Task<byte[]?> InvokePrimaryHandler(byte handlerIndex, byte[] args, bool awaitResponse = true, CancellationToken cancellationToken = default)
        {
            return await _protocolHandler.InvokePrimaryHandlerAsync(handlerIndex, args, awaitResponse, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Performs the initial handshake to gain special access to the PLC.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True if the handshake was successful, false otherwise.</returns>
        public async Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken = default)
        {
            return await _protocolHandler.PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets the version of the PLC bootloader.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The version string.</returns>
        public async Task<string> GetVersion(CancellationToken cancellationToken = default)
        {
            return await _protocolHandler.GetVersionAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes data to IRAM.
        /// </summary>
        /// <param name="targetAddress">The target address in IRAM.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteToIram(uint targetAddress, byte[] contents, CancellationToken cancellationToken = default)
        {
            await _memoryManager.WriteToIramAsync(targetAddress, contents, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Installs the stager payload onto the PLC.
        /// </summary>
        /// <param name="stagerPayload">The stager payload to install.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task InstallStager(byte[] stagerPayload, CancellationToken cancellationToken = default)
        {
            await _stagerManager.InstallStagerAsync(stagerPayload, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a full message via the stager.
        /// </summary>
        /// <param name="msg">The message to send.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task SendFullMsgViaStager(byte[] msg, CancellationToken cancellationToken = default)
        {
            await _stagerManager.SendFullMsgViaStagerAsync(msg, cancellationToken).ConfigureAwait(false);
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
            return await _protocolHandler.InvokeAddHookAsync(hookNo, args, awaitResponse, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes data to the PLC via the stager.
        /// </summary>
        /// <param name="address">The address to write to.</param>
        /// <param name="contents">The data to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteViaStager(uint address, byte[] contents, CancellationToken cancellationToken = default)
        {
            await _stagerManager.WriteViaStagerAsync(address, contents, cancellationToken).ConfigureAwait(false);
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
            await _stagerManager.InstallAddHookViaStagerAsync(targetAddress, payload, newHookNo, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Receives a large amount of data from the PLC.
        /// </summary>
        /// <param name="progress">The progress reporter.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The received data.</returns>
        public async Task<byte[]> ReceiveMany(IProgress<long> progress, CancellationToken cancellationToken = default)
        {
            return await _memoryManager.ReceiveManyAsync(progress, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Dumps memory from the PLC at the specified address and length.
        /// </summary>
        /// <param name="address">The memory address to start dumping from.</param>
        /// <param name="length">The number of bytes to dump.</param>
        /// <param name="dumpMemPayload">The memory dumper payload binary.</param>
        /// <param name="progress">Progress reporter for the dump operation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The dumped memory data.</returns>
        /// <exception cref="InvalidOperationException">Thrown when not connected to PLC.</exception>
        /// <exception cref="ArgumentNullException">Thrown when dumpMemPayload is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
        public async Task<byte[]> DumpMemoryAsync(uint address, uint length, byte[] dumpMemPayload, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
        {
            return await _memoryManager.DumpMemoryAsync(address, length, dumpMemPayload, _stagerManager, progress, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sets the UART speed on the PLC to improve memory dump transfer rates.
        /// After changing the UART speed, the host serial connection must be reconfigured to match.
        /// </summary>
        /// <param name="baudRate">The target baud rate (38400, 57600, 115200, 230400, or 460800).</param>
        /// <param name="uartSpeedPayload">The UART speed reconfiguration payload binary.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if UART speed was successfully changed, false otherwise.</returns>
        /// <exception cref="InvalidOperationException">Thrown when not connected to PLC.</exception>
        /// <exception cref="ArgumentNullException">Thrown when uartSpeedPayload is null.</exception>
        /// <exception cref="ArgumentException">Thrown when baud rate is invalid.</exception>
        public async Task<bool> SetUartSpeedAsync(uint baudRate, byte[] uartSpeedPayload, CancellationToken cancellationToken = default)
        {
            return await _memoryManager.SetUartSpeedAsync(baudRate, uartSpeedPayload, _stagerManager, cancellationToken).ConfigureAwait(false);
        }

        #region IDisposable Implementation
        private bool _disposed = false;

        /// <summary>
        /// Releases all resources used by the PlcClient.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the PlcClient and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    _channel?.Dispose();
                }

                _disposed = true;
            }
        }
        #endregion
    }
}
