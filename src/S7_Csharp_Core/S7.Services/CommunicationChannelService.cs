using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Ports;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for managing communication channels including socat and serial port operations.
    /// </summary>
    public class CommunicationChannelService(
        ILogger<CommunicationChannelService> logger) : ICommunicationChannelService
    {
        private readonly ILogger<CommunicationChannelService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private SocatStatus _currentStatus = SocatStatus.Stopped;

        /// <inheritdoc />
        public event EventHandler<SocatStatusChangedEventArgs>? SocatStatusChanged;

        /// <inheritdoc />
        public event EventHandler<SerialPortsChangedEventArgs>? SerialPortsChanged;

        /// <inheritdoc />
        public async Task<Result<SocatStartResult>> StartSocatAsync(
            SocatOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();

            _logger.LogInformation("Starting socat bridge. Port: {SerialPort}, TCP: {TcpPort}, Baud: {BaudRate}",
                options.SerialPort, options.TcpPort, options.BaudRate);

            try
            {
                SetSocatStatus(SocatStatus.Starting);

                // Validate options
                var validationResult = ValidateChannelConfiguration(new CommunicationChannelConfig
                {
                    Mode = "Serial",
                    SerialPort = options.SerialPort,
                    BaudRate = options.BaudRate,
                    Port = options.TcpPort
                });

                if (!validationResult.IsSuccess)
                {
                    SetSocatStatus(SocatStatus.Error);
                    return Result<SocatStartResult>.Failure($"Invalid socat options: {validationResult.Error.Message}");
                }

                // Simulate socat start for now - this will be implemented properly later
                await Task.Delay(100, cancellationToken);

                stopwatch.Stop();
                SetSocatStatus(SocatStatus.Running);

                var result = new SocatStartResult(
                    ProcessId: 0,
                    SerialPort: options.SerialPort,
                    TcpPort: options.TcpPort,
                    StartTime: DateTime.UtcNow,
                    CommandLine: $"socat {options.SerialPort} TCP-LISTEN:{options.TcpPort}");

                _logger.LogInformation("Socat bridge started successfully in {Duration}ms. Port: {SerialPort} -> TCP:{TcpPort}",
                    stopwatch.ElapsedMilliseconds, options.SerialPort, options.TcpPort);

                return Result<SocatStartResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                SetSocatStatus(SocatStatus.Stopped);
                _logger.LogWarning("Socat start operation was cancelled");
                return Result<SocatStartResult>.Failure("Socat start operation was cancelled");
            }
            catch (Exception ex)
            {
                SetSocatStatus(SocatStatus.Error);
                _logger.LogError(ex, "Failed to start socat bridge");
                return Result<SocatStartResult>.Failure($"Failed to start socat: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result> StopSocatAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();

            _logger.LogInformation("Stopping socat bridge");

            try
            {
                SetSocatStatus(SocatStatus.Stopping);

                // Simulate socat stop for now
                await Task.Delay(50, cancellationToken);

                stopwatch.Stop();
                SetSocatStatus(SocatStatus.Stopped);

                _logger.LogInformation("Socat bridge stopped successfully in {Duration}ms", stopwatch.ElapsedMilliseconds);
                return Result.Success();
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Socat stop operation was cancelled");
                return Result.Failure("Socat stop operation was cancelled");
            }
            catch (Exception ex)
            {
                SetSocatStatus(SocatStatus.Error);
                _logger.LogError(ex, "Failed to stop socat bridge");
                return Result.Failure($"Failed to stop socat: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public SocatStatus GetSocatStatus()
        {
            return _currentStatus;
        }

        /// <inheritdoc />
        public async Task<Result<SerialPortDiscoveryResult>> DiscoverSerialPortsAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();

            _logger.LogDebug("Discovering available serial ports");

            try
            {
                var portNames = await Task.Run(() => SerialPort.GetPortNames(), cancellationToken).ConfigureAwait(false);
                
                var portInfos = portNames.Select(portName => new SerialPortInfo(
                    PortName: portName,
                    Description: $"Serial Port {portName}",
                    IsAvailable: true,
                    Properties: new Dictionary<string, object>
                    {
                        ["DiscoveredAt"] = DateTime.UtcNow,
                        ["SystemName"] = portName
                    })).ToList();

                stopwatch.Stop();

                var result = new SerialPortDiscoveryResult(
                    AvailablePorts: portInfos,
                    DiscoveryTime: DateTime.UtcNow,
                    DiscoveryDuration: stopwatch.Elapsed);

                _logger.LogInformation("Discovered {PortCount} serial ports in {Duration}ms",
                    portInfos.Count, stopwatch.ElapsedMilliseconds);

                // Raise event for port discovery
                SerialPortsChanged?.Invoke(this, new SerialPortsChangedEventArgs(portInfos));

                return Result<SerialPortDiscoveryResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Serial port discovery was cancelled");
                return Result<SerialPortDiscoveryResult>.Failure("Serial port discovery was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to discover serial ports");
                return Result<SerialPortDiscoveryResult>.Failure($"Failed to discover serial ports: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<SerialPortTestResult>> TestSerialPortAsync(
            SerialPortConfig portConfig,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(portConfig);

            var stopwatch = Stopwatch.StartNew();

            _logger.LogDebug("Testing serial port connection. Port: {PortName}, Baud: {BaudRate}",
                portConfig.PortName, portConfig.BaudRate);

            try
            {
                var testResult = await Task.Run(() =>
                {
                    try
                    {
                        using var serialPort = new SerialPort(portConfig.PortName, portConfig.BaudRate);
                        
                        // Convert string enums to actual enum values
                        if (Enum.TryParse<Parity>(portConfig.Parity, out var parity))
                            serialPort.Parity = parity;
                        
                        if (Enum.TryParse<StopBits>(portConfig.StopBits, out var stopBits))
                            serialPort.StopBits = stopBits;
                        
                        if (Enum.TryParse<Handshake>(portConfig.FlowControl, out var handshake))
                            serialPort.Handshake = handshake;

                        serialPort.Open();
                        
                        // Brief test - just opening and closing
                        Thread.Sleep(100);
                        
                        serialPort.Close();
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }, cancellationToken).ConfigureAwait(false);

                stopwatch.Stop();

                var result = new SerialPortTestResult(
                    IsSuccessful: testResult,
                    PortName: portConfig.PortName,
                    TestDuration: stopwatch.Elapsed,
                    ErrorMessage: testResult ? null : "Failed to open serial port",
                    TestMetrics: new Dictionary<string, object>
                    {
                        ["BaudRate"] = portConfig.BaudRate,
                        ["Parity"] = portConfig.Parity,
                        ["StopBits"] = portConfig.StopBits,
                        ["FlowControl"] = portConfig.FlowControl,
                        ["TestTime"] = DateTime.UtcNow
                    });

                _logger.LogInformation("Serial port test completed. Port: {PortName}, Success: {IsSuccessful}, Duration: {Duration}ms",
                    portConfig.PortName, testResult, stopwatch.ElapsedMilliseconds);

                return Result<SerialPortTestResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Serial port test was cancelled");
                return Result<SerialPortTestResult>.Failure("Serial port test was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to test serial port {PortName}", portConfig.PortName);
                
                var result = new SerialPortTestResult(
                    IsSuccessful: false,
                    PortName: portConfig.PortName,
                    TestDuration: stopwatch.Elapsed,
                    ErrorMessage: ex.Message,
                    TestMetrics: new Dictionary<string, object>
                    {
                        ["Exception"] = ex.GetType().Name,
                        ["TestTime"] = DateTime.UtcNow
                    });

                return Result<SerialPortTestResult>.Success(result);
            }
        }

        /// <inheritdoc />
        public Result<bool> ValidateChannelConfiguration(CommunicationChannelConfig channelConfig)
        {
            ArgumentNullException.ThrowIfNull(channelConfig);

            try
            {
                var errors = new List<string>();

                // Validate mode
                if (string.IsNullOrWhiteSpace(channelConfig.Mode))
                {
                    errors.Add("Communication mode is required");
                }
                else if (channelConfig.Mode.ToUpperInvariant() == "SERIAL")
                {
                    // Validate serial port configuration
                    if (string.IsNullOrWhiteSpace(channelConfig.SerialPort))
                        errors.Add("Serial port name is required for serial communication");

                    if (channelConfig.BaudRate <= 0)
                        errors.Add("Baud rate must be greater than 0");

                    if (!Enum.TryParse<Parity>(channelConfig.Parity, out _))
                        errors.Add($"Invalid parity setting: {channelConfig.Parity}");

                    if (!Enum.TryParse<StopBits>(channelConfig.StopBits, out _))
                        errors.Add($"Invalid stop bits setting: {channelConfig.StopBits}");

                    if (!Enum.TryParse<Handshake>(channelConfig.FlowControl, out _))
                        errors.Add($"Invalid flow control setting: {channelConfig.FlowControl}");
                }
                else if (channelConfig.Mode.ToUpperInvariant() == "TCP")
                {
                    // Validate TCP configuration
                    if (string.IsNullOrWhiteSpace(channelConfig.Host))
                        errors.Add("Host is required for TCP communication");

                    if (channelConfig.Port <= 0 || channelConfig.Port > 65535)
                        errors.Add("Port must be between 1 and 65535");
                }
                else
                {
                    errors.Add($"Unsupported communication mode: {channelConfig.Mode}");
                }

                if (errors.Any())
                {
                    var errorMessage = string.Join("; ", errors);
                    _logger.LogWarning("Channel configuration validation failed: {Errors}", errorMessage);
                    return Result<bool>.Failure(errorMessage);
                }

                _logger.LogDebug("Channel configuration validation passed for mode: {Mode}", channelConfig.Mode);
                return Result<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating channel configuration");
                return Result<bool>.Failure($"Validation error: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public SocatProcessInfo GetSocatProcessInfo()
        {
            try
            {
                // For now, return empty process info - this will be implemented properly later
                var processInfo = new SocatProcessInfo(
                    ProcessIds: new List<int>(),
                    TotalProcesses: 0,
                    QueryTime: DateTime.UtcNow);

                _logger.LogDebug("Found {ProcessCount} socat processes", 0);
                return processInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get socat process information");
                return new SocatProcessInfo(
                    ProcessIds: new List<int>(),
                    TotalProcesses: 0,
                    QueryTime: DateTime.UtcNow);
            }
        }

        /// <inheritdoc />
        public async Task<Result<int>> KillAllSocatProcessesAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();

            _logger.LogInformation("Killing all socat processes");

            try
            {
                var processInfo = GetSocatProcessInfo();
                var initialProcessCount = processInfo.TotalProcesses;

                // Simulate killing processes for now
                await Task.Delay(50, cancellationToken);

                stopwatch.Stop();

                // Update status if we were running
                if (_currentStatus == SocatStatus.Running)
                {
                    SetSocatStatus(SocatStatus.Stopped);
                }

                _logger.LogInformation("Killed {ProcessCount} socat processes in {Duration}ms",
                    initialProcessCount, stopwatch.ElapsedMilliseconds);

                return Result<int>.Success(initialProcessCount);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Kill socat processes operation was cancelled");
                return Result<int>.Failure("Kill operation was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to kill socat processes");
                return Result<int>.Failure($"Failed to kill socat processes: {ex.Message}");
            }
        }

        private void SetSocatStatus(SocatStatus newStatus)
        {
            var previousStatus = _currentStatus;
            _currentStatus = newStatus;

            if (previousStatus != newStatus)
            {
                _logger.LogInformation("Socat status changed from {PreviousStatus} to {CurrentStatus}",
                    previousStatus, newStatus);

                SocatStatusChanged?.Invoke(this, new SocatStatusChangedEventArgs(
                    previousStatus, newStatus, $"Status changed from {previousStatus} to {newStatus}"));
            }
        }
    }
}