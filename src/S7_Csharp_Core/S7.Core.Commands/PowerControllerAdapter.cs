using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands
{
    /// <summary>
    /// Adapter for the existing PowerController to implement IPowerController interface.
    /// </summary>
    public class PowerControllerAdapter : IPowerController, IDisposable
    {
        private readonly ILogger<PowerControllerAdapter> _logger;
        private S7_Csharp_Utility.Services.PowerController? _powerController;

        /// <summary>
        /// Initializes a new instance of the PowerControllerAdapter class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        public PowerControllerAdapter(ILogger<PowerControllerAdapter> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Performs a power cycle operation.
        /// </summary>
        /// <param name="host">The Modbus host</param>
        /// <param name="port">The Modbus port</param>
        /// <param name="coil">The coil address</param>
        /// <param name="delaySeconds">The delay after power cycle</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A task representing the operation</returns>
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
                // Create a new power controller instance for this operation
                _powerController = new S7_Csharp_Utility.Services.PowerController(
                    (message, isError) =>
                    {
                        if (isError)
                            _logger.LogError("PowerController: {Message}", message);
                        else
                            _logger.LogInformation("PowerController: {Message}", message);
                    });

                // Connect to the Modbus host
                await _powerController.ConnectAsync(host, port).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                if (!_powerController.IsConnected)
                {
                    throw new InvalidOperationException($"Failed to connect to Modbus host {host}:{port}");
                }

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
                throw;
            }
            finally
            {
                // Clean up the power controller
                if (_powerController != null)
                {
                    try
                    {
                        _powerController.Disconnect();
                        _powerController.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error during power controller cleanup");
                    }
                    finally
                    {
                        _powerController = null;
                    }
                }
            }
        }

        /// <summary>
        /// Disposes the adapter and any resources it holds.
        /// </summary>
        public void Dispose()
        {
            if (_powerController != null)
            {
                try
                {
                    _powerController.Disconnect();
                    _powerController.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error during disposal");
                }
                finally
                {
                    _powerController = null;
                }
            }
        }
    }
}