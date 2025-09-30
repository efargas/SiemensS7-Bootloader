using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands
{
    /// <summary>
    /// Adapter for the existing PowerController to implement IPowerController interface.
    /// Manages a persistent connection to the power controller.
    /// </summary>
    public class PowerControllerAdapter : IPowerController, IDisposable
    {
        private readonly ILogger<PowerControllerAdapter> _logger;
        private readonly S7_Csharp_Utility.Services.PowerController _powerController;
        private string? _currentHost;
        private int _currentPort;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the PowerControllerAdapter class.
        /// </summary>
        /// <param name="logger">The logger for the adapter.</param>
        /// <param name="powerControllerLogger">The logger for the underlying power controller.</param>
        public PowerControllerAdapter(ILogger<PowerControllerAdapter> logger, ILogger<S7_Csharp_Utility.Services.PowerController> powerControllerLogger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _powerController = new S7_Csharp_Utility.Services.PowerController(powerControllerLogger ?? throw new ArgumentNullException(nameof(powerControllerLogger)));
        }

        /// <summary>
        /// Performs a power cycle operation.
        /// </summary>
        /// <param name="host">The Modbus host.</param>
        /// <param name="port">The Modbus port.</param>
        /// <param name="coil">The coil address.</param>
        /// <param name="delaySeconds">The delay after power cycle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the operation.</returns>
        public async Task PowerCycleAsync(string host, int port, int coil, int delaySeconds, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(host);

            if (port <= 0 || port > 65535)
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535");

            if (coil < 0 || coil > 65535)
                throw new ArgumentOutOfRangeException(nameof(coil), "Coil must be between 0 and 65535");

            if (delaySeconds < 0)
                throw new ArgumentOutOfRangeException(nameof(delaySeconds), "Delay must be non-negative");

            _logger.LogInformation("Starting power cycle operation: Host={Host}, Port={Port}, Coil={Coil}, Delay={DelaySeconds}s",
                host, port, coil, delaySeconds);

            try
            {
                // Connect or reconnect if the host/port has changed or if we are not connected.
                if (!_powerController.IsConnected || _currentHost != host || _currentPort != port)
                {
                    _powerController.Disconnect();
                    await _powerController.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
                    _currentHost = host;
                    _currentPort = port;
                }

                cancellationToken.ThrowIfCancellationRequested();

                // Turn power OFF
                _logger.LogInformation("Turning power OFF (coil {Coil})", coil);
                await _powerController.SetPowerAsync((ushort)coil, false).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                // Wait for the specified delay
                if (delaySeconds > 0)
                {
                    _logger.LogInformation("Waiting {DelaySeconds} seconds before turning power back ON", delaySeconds);
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken).ConfigureAwait(false);
                }

                // Turn power ON
                _logger.LogInformation("Turning power ON (coil {Coil})", coil);
                await _powerController.SetPowerAsync((ushort)coil, true).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                _logger.LogInformation("Power cycle completed successfully");
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Power cycle operation was cancelled");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Power cycle operation failed");
                // Disconnect on failure to ensure a clean state for the next attempt.
                _powerController.Disconnect();
                _currentHost = null;
                throw;
            }
        }

        /// <summary>
        /// Disposes the adapter and any resources it holds.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _powerController.Dispose();
            }

            _disposed = true;
        }
    }
}