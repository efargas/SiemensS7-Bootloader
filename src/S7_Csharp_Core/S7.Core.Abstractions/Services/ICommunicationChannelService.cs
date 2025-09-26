using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Abstractions.Configuration;
using S7.Utils;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Service interface for managing communication channels including socat and serial port operations.
    /// </summary>
    public interface ICommunicationChannelService
    {
        /// <summary>
        /// Starts a socat bridge for serial-to-TCP communication.
        /// </summary>
        /// <param name="options">The socat configuration options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the socat start operation result</returns>
        Task<Result<SocatStartResult>> StartSocatAsync(
            SocatOptions options,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Stops the currently running socat bridge.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the socat stop operation result</returns>
        Task<Result> StopSocatAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the current status of the socat bridge.
        /// </summary>
        /// <returns>The current socat status</returns>
        SocatStatus GetSocatStatus();

        /// <summary>
        /// Discovers available serial ports on the system.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the serial port discovery result</returns>
        Task<Result<SerialPortDiscoveryResult>> DiscoverSerialPortsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests a serial port connection with the specified configuration.
        /// </summary>
        /// <param name="portConfig">The serial port configuration to test</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the serial port test result</returns>
        Task<Result<SerialPortTestResult>> TestSerialPortAsync(
            SerialPortConfig portConfig,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates a communication channel configuration.
        /// </summary>
        /// <param name="channelConfig">The channel configuration to validate</param>
        /// <returns>The validation result</returns>
        Result<bool> ValidateChannelConfiguration(CommunicationChannelConfig channelConfig);

        /// <summary>
        /// Gets information about running socat processes.
        /// </summary>
        /// <returns>Information about running socat processes</returns>
        SocatProcessInfo GetSocatProcessInfo();

        /// <summary>
        /// Kills all running socat processes.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the kill operation result</returns>
        Task<Result<int>> KillAllSocatProcessesAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Event raised when the socat status changes.
        /// </summary>
        event EventHandler<SocatStatusChangedEventArgs>? SocatStatusChanged;

        /// <summary>
        /// Event raised when serial ports are discovered or changed.
        /// </summary>
        event EventHandler<SerialPortsChangedEventArgs>? SerialPortsChanged;
    }

    /// <summary>
    /// Options for configuring socat operations.
    /// </summary>
    public record SocatOptions(
        string SerialPort,
        int TcpPort,
        int BaudRate = 38400,
        string Parity = "Even",
        string StopBits = "One",
        string FlowControl = "None",
        bool Verbose = true,
        bool HexDump = true,
        int BlockSize = 4,
        TimeSpan Timeout = default)
    {
        public SocatOptions() : this(string.Empty, 1238, 38400, "Even", "One", "None", true, true, 4, TimeSpan.FromSeconds(30)) { }
    }

    /// <summary>
    /// Configuration for serial port operations.
    /// </summary>
    public record SerialPortConfig(
        string PortName,
        int BaudRate = 38400,
        string Parity = "Even",
        string StopBits = "One",
        string FlowControl = "None",
        TimeSpan Timeout = default)
    {
        public SerialPortConfig() : this(string.Empty, 38400, "Even", "One", "None", TimeSpan.FromSeconds(5)) { }
    }

    /// <summary>
    /// Result of starting a socat bridge.
    /// </summary>
    public record SocatStartResult(
        int ProcessId,
        string SerialPort,
        int TcpPort,
        DateTime StartTime,
        string CommandLine);

    /// <summary>
    /// Result of discovering serial ports.
    /// </summary>
    public record SerialPortDiscoveryResult(
        List<SerialPortInfo> AvailablePorts,
        DateTime DiscoveryTime,
        TimeSpan DiscoveryDuration);

    /// <summary>
    /// Information about a discovered serial port.
    /// </summary>
    public record SerialPortInfo(
        string PortName,
        string Description,
        bool IsAvailable,
        Dictionary<string, object> Properties);

    /// <summary>
    /// Result of testing a serial port connection.
    /// </summary>
    public record SerialPortTestResult(
        bool IsSuccessful,
        string PortName,
        TimeSpan TestDuration,
        string? ErrorMessage,
        Dictionary<string, object> TestMetrics);

    /// <summary>
    /// Information about running socat processes.
    /// </summary>
    public record SocatProcessInfo(
        List<int> ProcessIds,
        int TotalProcesses,
        DateTime QueryTime);

    /// <summary>
    /// Enumeration of possible socat status values.
    /// </summary>
    public enum SocatStatus
    {
        /// <summary>
        /// Socat is not running.
        /// </summary>
        Stopped = 0,

        /// <summary>
        /// Socat is starting up.
        /// </summary>
        Starting = 1,

        /// <summary>
        /// Socat is running normally.
        /// </summary>
        Running = 2,

        /// <summary>
        /// Socat is stopping.
        /// </summary>
        Stopping = 3,

        /// <summary>
        /// Socat is in an error state.
        /// </summary>
        Error = 4
    }

    /// <summary>
    /// Event arguments for socat status changes.
    /// </summary>
    public class SocatStatusChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous socat status.
        /// </summary>
        public SocatStatus PreviousStatus { get; }

        /// <summary>
        /// Gets the current socat status.
        /// </summary>
        public SocatStatus CurrentStatus { get; }

        /// <summary>
        /// Gets the timestamp of the status change.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets additional information about the status change.
        /// </summary>
        public string? Message { get; }

        /// <summary>
        /// Initializes a new instance of the SocatStatusChangedEventArgs class.
        /// </summary>
        /// <param name="previousStatus">The previous socat status</param>
        /// <param name="currentStatus">The current socat status</param>
        /// <param name="message">Additional information about the status change</param>
        public SocatStatusChangedEventArgs(
            SocatStatus previousStatus,
            SocatStatus currentStatus,
            string? message = null)
        {
            PreviousStatus = previousStatus;
            CurrentStatus = currentStatus;
            Timestamp = DateTime.UtcNow;
            Message = message;
        }
    }

    /// <summary>
    /// Event arguments for serial port changes.
    /// </summary>
    public class SerialPortsChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the list of available serial ports.
        /// </summary>
        public List<SerialPortInfo> AvailablePorts { get; }

        /// <summary>
        /// Gets the timestamp of the change.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Initializes a new instance of the SerialPortsChangedEventArgs class.
        /// </summary>
        /// <param name="availablePorts">The list of available serial ports</param>
        public SerialPortsChangedEventArgs(List<SerialPortInfo> availablePorts)
        {
            AvailablePorts = availablePorts;
            Timestamp = DateTime.UtcNow;
        }
    }
}