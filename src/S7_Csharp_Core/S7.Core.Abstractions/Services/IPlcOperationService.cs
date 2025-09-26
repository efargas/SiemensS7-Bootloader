using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Validation;
using S7.Utils;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Defines the contract for PLC operation services that handle high-level PLC interactions.
    /// </summary>
    public interface IPlcOperationService
    {
        /// <summary>
        /// Executes a complete exploit sequence on the target PLC.
        /// </summary>
        /// <param name="options">The exploit sequence options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the exploit sequence result</returns>
        Task<Result<ExploitSequenceResult>> ExecuteExploitSequenceAsync(
            ExploitSequenceOptions options, 
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Establishes a connection to the PLC using the specified configuration.
        /// </summary>
        /// <param name="channelConfig">The communication channel configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the connection result</returns>
        Task<Result<PlcConnectionInfo>> ConnectAsync(
            CommunicationChannelConfig channelConfig, 
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Disconnects from the currently connected PLC.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the disconnection operation</returns>
        Task<Result> DisconnectAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs a handshake with the connected PLC to verify communication.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the handshake result</returns>
        Task<Result<HandshakeResult>> PerformHandshakeAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Reads memory from the PLC at the specified address.
        /// </summary>
        /// <param name="address">The memory address to read from</param>
        /// <param name="length">The number of bytes to read</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the memory read result</returns>
        Task<Result<byte[]>> ReadMemoryAsync(
            uint address, 
            uint length, 
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Writes data to the PLC memory at the specified address.
        /// </summary>
        /// <param name="address">The memory address to write to</param>
        /// <param name="data">The data to write</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the memory write result</returns>
        Task<Result> WriteMemoryAsync(
            uint address, 
            byte[] data, 
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves information about the connected PLC.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the PLC information result</returns>
        Task<Result<PlcInfo>> GetPlcInfoAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates the PLC connection and configuration.
        /// </summary>
        /// <param name="channelConfig">The communication channel configuration to validate</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the validation result</returns>
        Task<Result<ValidationResult>> ValidateConnectionAsync(
            CommunicationChannelConfig channelConfig, 
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the current connection status of the PLC.
        /// </summary>
        /// <returns>The current connection status</returns>
        PlcConnectionStatus GetConnectionStatus();

        /// <summary>
        /// Event raised when the PLC connection status changes.
        /// </summary>
        event EventHandler<PlcConnectionStatusChangedEventArgs>? ConnectionStatusChanged;

        /// <summary>
        /// Event raised when a PLC operation completes.
        /// </summary>
        event EventHandler<PlcOperationCompletedEventArgs>? OperationCompleted;
    }

    /// <summary>
    /// Options for executing an exploit sequence.
    /// </summary>
    public class ExploitSequenceOptions
    {
        /// <summary>
        /// Gets or sets the communication channel configuration.
        /// </summary>
        public CommunicationChannelConfig ChannelConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets the list of payloads to execute in sequence.
        /// </summary>
        public List<string> PayloadPaths { get; set; } = new();

        /// <summary>
        /// Gets or sets whether to perform a handshake before execution.
        /// </summary>
        public bool PerformHandshake { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to validate each step before execution.
        /// </summary>
        public bool ValidateSteps { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for the entire sequence in milliseconds.
        /// </summary>
        public int TimeoutMs { get; set; } = 300000; // 5 minutes

        /// <summary>
        /// Gets or sets whether to continue on step failure.
        /// </summary>
        public bool ContinueOnFailure { get; set; } = false;

        /// <summary>
        /// Gets or sets the power controller configuration for power cycling.
        /// </summary>
        public PowerControllerConfig? PowerConfig { get; set; }

        /// <summary>
        /// Gets or sets whether to perform power cycling before the sequence.
        /// </summary>
        public bool PowerCycleBeforeSequence { get; set; } = false;

        /// <summary>
        /// Gets or sets whether to perform power cycling after the sequence.
        /// </summary>
        public bool PowerCycleAfterSequence { get; set; } = false;
    }

    /// <summary>
    /// Result of an exploit sequence execution.
    /// </summary>
    public class ExploitSequenceResult
    {
        /// <summary>
        /// Gets or sets whether the sequence completed successfully.
        /// </summary>
        public bool IsSuccess { get; set; }

        /// <summary>
        /// Gets or sets the number of steps executed.
        /// </summary>
        public int StepsExecuted { get; set; }

        /// <summary>
        /// Gets or sets the total number of steps in the sequence.
        /// </summary>
        public int TotalSteps { get; set; }

        /// <summary>
        /// Gets or sets the duration of the sequence execution.
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Gets or sets the results of individual steps.
        /// </summary>
        public List<ExploitStepResult> StepResults { get; set; } = new();

        /// <summary>
        /// Gets or sets any warnings generated during execution.
        /// </summary>
        public List<string> Warnings { get; set; } = new();

        /// <summary>
        /// Gets or sets the error message if the sequence failed.
        /// </summary>
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Result of an individual exploit step.
    /// </summary>
    public class ExploitStepResult
    {
        /// <summary>
        /// Gets or sets the step name or description.
        /// </summary>
        public string StepName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether the step completed successfully.
        /// </summary>
        public bool IsSuccess { get; set; }

        /// <summary>
        /// Gets or sets the duration of the step execution.
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Gets or sets the error message if the step failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets additional data returned by the step.
        /// </summary>
        public Dictionary<string, object> Data { get; set; } = new();
    }

    /// <summary>
    /// Information about a PLC connection.
    /// </summary>
    public class PlcConnectionInfo
    {
        /// <summary>
        /// Gets or sets the connection identifier.
        /// </summary>
        public string ConnectionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the PLC address or endpoint.
        /// </summary>
        public string Address { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the connection type (TCP, Serial, etc.).
        /// </summary>
        public string ConnectionType { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the timestamp when the connection was established.
        /// </summary>
        public DateTime ConnectedAt { get; set; }

        /// <summary>
        /// Gets or sets whether the connection is currently active.
        /// </summary>
        public bool IsActive { get; set; }

        /// <summary>
        /// Gets or sets additional connection properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    /// <summary>
    /// Result of a handshake operation.
    /// </summary>
    public class HandshakeResult
    {
        /// <summary>
        /// Gets or sets whether the handshake was successful.
        /// </summary>
        public bool IsSuccess { get; set; }

        /// <summary>
        /// Gets or sets the handshake duration.
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Gets or sets the PLC response data.
        /// </summary>
        public byte[]? ResponseData { get; set; }

        /// <summary>
        /// Gets or sets the protocol version detected.
        /// </summary>
        public string? ProtocolVersion { get; set; }

        /// <summary>
        /// Gets or sets additional handshake information.
        /// </summary>
        public Dictionary<string, object> AdditionalInfo { get; set; } = new();
    }

    /// <summary>
    /// Information about a PLC.
    /// </summary>
    public class PlcInfo
    {
        /// <summary>
        /// Gets or sets the PLC model or type.
        /// </summary>
        public string Model { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the firmware version.
        /// </summary>
        public string FirmwareVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the hardware version.
        /// </summary>
        public string HardwareVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the serial number.
        /// </summary>
        public string SerialNumber { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the supported protocol versions.
        /// </summary>
        public List<string> SupportedProtocols { get; set; } = new();

        /// <summary>
        /// Gets or sets the memory layout information.
        /// </summary>
        public Dictionary<string, object> MemoryLayout { get; set; } = new();

        /// <summary>
        /// Gets or sets additional PLC properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    /// <summary>
    /// Represents the connection status of a PLC.
    /// </summary>
    public enum PlcConnectionStatus
    {
        /// <summary>
        /// The PLC is disconnected.
        /// </summary>
        Disconnected = 0,

        /// <summary>
        /// The PLC is connecting.
        /// </summary>
        Connecting = 1,

        /// <summary>
        /// The PLC is connected.
        /// </summary>
        Connected = 2,

        /// <summary>
        /// The PLC connection is in an error state.
        /// </summary>
        Error = 3,

        /// <summary>
        /// The PLC connection is being validated.
        /// </summary>
        Validating = 4
    }

    /// <summary>
    /// Event arguments for PLC connection status changes.
    /// </summary>
    public class PlcConnectionStatusChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous connection status.
        /// </summary>
        public PlcConnectionStatus PreviousStatus { get; }

        /// <summary>
        /// Gets the current connection status.
        /// </summary>
        public PlcConnectionStatus CurrentStatus { get; }

        /// <summary>
        /// Gets the timestamp of the status change.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets additional information about the status change.
        /// </summary>
        public string? Message { get; }

        /// <summary>
        /// Initializes a new instance of the PlcConnectionStatusChangedEventArgs class.
        /// </summary>
        /// <param name="previousStatus">The previous connection status</param>
        /// <param name="currentStatus">The current connection status</param>
        /// <param name="message">Additional information about the status change</param>
        public PlcConnectionStatusChangedEventArgs(
            PlcConnectionStatus previousStatus, 
            PlcConnectionStatus currentStatus, 
            string? message = null)
        {
            PreviousStatus = previousStatus;
            CurrentStatus = currentStatus;
            Timestamp = DateTime.UtcNow;
            Message = message;
        }
    }

    /// <summary>
    /// Event arguments for PLC operation completion.
    /// </summary>
    public class PlcOperationCompletedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the operation name.
        /// </summary>
        public string OperationName { get; }

        /// <summary>
        /// Gets whether the operation was successful.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the operation duration.
        /// </summary>
        public TimeSpan Duration { get; }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets additional operation data.
        /// </summary>
        public Dictionary<string, object> Data { get; }

        /// <summary>
        /// Initializes a new instance of the PlcOperationCompletedEventArgs class.
        /// </summary>
        /// <param name="operationName">The operation name</param>
        /// <param name="isSuccess">Whether the operation was successful</param>
        /// <param name="duration">The operation duration</param>
        /// <param name="errorMessage">The error message if the operation failed</param>
        /// <param name="data">Additional operation data</param>
        public PlcOperationCompletedEventArgs(
            string operationName, 
            bool isSuccess, 
            TimeSpan duration, 
            string? errorMessage = null, 
            Dictionary<string, object>? data = null)
        {
            OperationName = operationName;
            IsSuccess = isSuccess;
            Duration = duration;
            ErrorMessage = errorMessage;
            Data = data ?? new Dictionary<string, object>();
        }
    }
}