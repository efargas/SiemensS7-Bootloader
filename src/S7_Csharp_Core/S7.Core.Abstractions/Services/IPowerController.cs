using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Configuration;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Defines a contract for power controller operations.
    /// </summary>
    public interface IPowerController
    {
        /// <summary>
        /// Performs a power cycle operation (turn off, wait, turn on).
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power cycle operation</returns>
        Task PowerCycleAsync(PowerControllerConfig config, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the power state of the controlled device.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="powerOn">True to turn power on, false to turn power off</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power control operation</returns>
        Task SetPowerAsync(PowerControllerConfig config, bool powerOn, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the current power status of the controlled device.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power status check, returning true if power is on</returns>
        Task<bool> GetPowerStatusAsync(PowerControllerConfig config, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests the connection to the power controller.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the connection test, returning true if connection is successful</returns>
        Task<bool> TestConnectionAsync(PowerControllerConfig config, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Result of a power controller operation.
    /// </summary>
    public class PowerControllerResult
    {
        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccess { get; init; }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public string? ErrorMessage { get; init; }

        /// <summary>
        /// Gets the current power state after the operation.
        /// </summary>
        public bool? PowerState { get; init; }

        /// <summary>
        /// Gets the duration of the operation.
        /// </summary>
        public System.TimeSpan Duration { get; init; }

        /// <summary>
        /// Creates a successful power controller result.
        /// </summary>
        /// <param name="powerState">The current power state</param>
        /// <param name="duration">The operation duration</param>
        /// <returns>A successful result</returns>
        public static PowerControllerResult Success(bool? powerState = null, System.TimeSpan duration = default)
        {
            return new PowerControllerResult
            {
                IsSuccess = true,
                PowerState = powerState,
                Duration = duration
            };
        }

        /// <summary>
        /// Creates a failed power controller result.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <param name="duration">The operation duration</param>
        /// <returns>A failed result</returns>
        public static PowerControllerResult Failure(string errorMessage, System.TimeSpan duration = default)
        {
            return new PowerControllerResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage,
                Duration = duration
            };
        }
    }
}