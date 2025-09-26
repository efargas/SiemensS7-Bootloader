using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Represents the connection status of a power supply.
    /// </summary>
    public enum PowerSupplyConnectionStatus
    {
        /// <summary>
        /// The power supply is disconnected.
        /// </summary>
        Disconnected,
        
        /// <summary>
        /// The power supply is connecting.
        /// </summary>
        Connecting,
        
        /// <summary>
        /// The power supply is connected.
        /// </summary>
        Connected,
        
        /// <summary>
        /// The power supply connection has an error.
        /// </summary>
        Error
    }

    /// <summary>
    /// Represents the power state of a device.
    /// </summary>
    public enum PowerState
    {
        /// <summary>
        /// The device is powered off.
        /// </summary>
        Off,
        
        /// <summary>
        /// The device is powered on.
        /// </summary>
        On,
        
        /// <summary>
        /// The device power state is unknown.
        /// </summary>
        Unknown
    }

    /// <summary>
    /// Configuration for power supply connection.
    /// </summary>
    public class PowerSupplyConfig
    {
        /// <summary>
        /// Gets or sets the Modbus host address.
        /// </summary>
        public string Host { get; set; } = "localhost";
        
        /// <summary>
        /// Gets or sets the Modbus port.
        /// </summary>
        public int Port { get; set; } = 502;
        
        /// <summary>
        /// Gets or sets the Modbus slave ID.
        /// </summary>
        public byte SlaveId { get; set; } = 1;
        
        /// <summary>
        /// Gets or sets the coil address for power control.
        /// </summary>
        public ushort CoilAddress { get; set; } = 1;
        
        /// <summary>
        /// Gets or sets the connection timeout.
        /// </summary>
        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(10);
        
        /// <summary>
        /// Gets or sets the operation timeout.
        /// </summary>
        public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromSeconds(5);
    }

    /// <summary>
    /// Event arguments for power supply connection status changes.
    /// </summary>
    public class PowerSupplyConnectionStatusChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous connection status.
        /// </summary>
        public PowerSupplyConnectionStatus PreviousStatus { get; }
        
        /// <summary>
        /// Gets the current connection status.
        /// </summary>
        public PowerSupplyConnectionStatus CurrentStatus { get; }
        
        /// <summary>
        /// Gets the error message if the status is Error.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerSupplyConnectionStatusChangedEventArgs"/> class.
        /// </summary>
        public PowerSupplyConnectionStatusChangedEventArgs(
            PowerSupplyConnectionStatus previousStatus, 
            PowerSupplyConnectionStatus currentStatus, 
            string? errorMessage = null)
        {
            PreviousStatus = previousStatus;
            CurrentStatus = currentStatus;
            ErrorMessage = errorMessage;
        }
    }

    /// <summary>
    /// Event arguments for power state changes.
    /// </summary>
    public class PowerStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous power state.
        /// </summary>
        public PowerState PreviousState { get; }
        
        /// <summary>
        /// Gets the current power state.
        /// </summary>
        public PowerState CurrentState { get; }
        
        /// <summary>
        /// Gets the coil address that was changed.
        /// </summary>
        public ushort CoilAddress { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerStateChangedEventArgs"/> class.
        /// </summary>
        public PowerStateChangedEventArgs(PowerState previousState, PowerState currentState, ushort coilAddress)
        {
            PreviousState = previousState;
            CurrentState = currentState;
            CoilAddress = coilAddress;
        }
    }

    /// <summary>
    /// Result of a power operation.
    /// </summary>
    public class PowerOperationResult
    {
        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccess { get; }
        
        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public string? ErrorMessage { get; }
        
        /// <summary>
        /// Gets the duration of the operation.
        /// </summary>
        public TimeSpan Duration { get; }
        
        /// <summary>
        /// Gets the final power state after the operation.
        /// </summary>
        public PowerState FinalState { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerOperationResult"/> class.
        /// </summary>
        public PowerOperationResult(bool isSuccess, PowerState finalState, TimeSpan duration, string? errorMessage = null)
        {
            IsSuccess = isSuccess;
            FinalState = finalState;
            Duration = duration;
            ErrorMessage = errorMessage;
        }

        /// <summary>
        /// Creates a successful power operation result.
        /// </summary>
        public static PowerOperationResult Success(PowerState finalState, TimeSpan duration) =>
            new(true, finalState, duration);

        /// <summary>
        /// Creates a failed power operation result.
        /// </summary>
        public static PowerOperationResult Failure(string errorMessage, PowerState finalState, TimeSpan duration) =>
            new(false, finalState, duration, errorMessage);
    }

    /// <summary>
    /// Service interface for power supply operations.
    /// </summary>
    public interface IPowerSupplyService
    {
        /// <summary>
        /// Gets the current connection status.
        /// </summary>
        PowerSupplyConnectionStatus ConnectionStatus { get; }
        
        /// <summary>
        /// Gets a value indicating whether the power supply is connected.
        /// </summary>
        bool IsConnected { get; }
        
        /// <summary>
        /// Gets the current power supply configuration.
        /// </summary>
        PowerSupplyConfig? CurrentConfig { get; }

        /// <summary>
        /// Occurs when the connection status changes.
        /// </summary>
        event EventHandler<PowerSupplyConnectionStatusChangedEventArgs>? ConnectionStatusChanged;
        
        /// <summary>
        /// Occurs when a power state changes.
        /// </summary>
        event EventHandler<PowerStateChangedEventArgs>? PowerStateChanged;

        /// <summary>
        /// Connects to the power supply with the specified configuration.
        /// </summary>
        /// <param name="config">The power supply configuration.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task<bool> ConnectAsync(PowerSupplyConfig config, CancellationToken cancellationToken = default);

        /// <summary>
        /// Disconnects from the power supply.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task DisconnectAsync();

        /// <summary>
        /// Sets the power state of the specified coil.
        /// </summary>
        /// <param name="coilAddress">The coil address.</param>
        /// <param name="powerOn">True to turn on, false to turn off.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the operation result.</returns>
        Task<PowerOperationResult> SetPowerAsync(ushort coilAddress, bool powerOn, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the current power state of the specified coil.
        /// </summary>
        /// <param name="coilAddress">The coil address.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the power state.</returns>
        Task<PowerState> GetPowerStateAsync(ushort coilAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs a power cycle operation (turn off, wait, turn on).
        /// </summary>
        /// <param name="coilAddress">The coil address.</param>
        /// <param name="delayBetweenStates">The delay between turning off and on.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the operation result.</returns>
        Task<PowerOperationResult> PowerCycleAsync(ushort coilAddress, TimeSpan delayBetweenStates, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests the connection to the power supply.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with the test result.</returns>
        Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets diagnostic information about the power supply connection.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation with diagnostic information.</returns>
        Task<string> GetDiagnosticInfoAsync(CancellationToken cancellationToken = default);
    }
}