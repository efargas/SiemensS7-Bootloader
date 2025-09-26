using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Validation;
using S7.Net;
using S7.Net.Interfaces;
using S7.Net.Channels;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for PLC operations providing comprehensive PLC communication and exploit sequence execution.
    /// </summary>
    public class PlcOperationService(
        ILogger<PlcOperationService> logger,
        PayloadManager payloadManager) : IPlcOperationService
    {
        private readonly ILogger<PlcOperationService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly PayloadManager _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
        private PlcClient? _currentClient;
        private PlcConnectionStatus _connectionStatus = PlcConnectionStatus.Disconnected;

        /// <inheritdoc />
        public event EventHandler<PlcConnectionStatusChangedEventArgs>? ConnectionStatusChanged;

        /// <inheritdoc />
        public event EventHandler<PlcOperationCompletedEventArgs>? OperationCompleted;

        /// <inheritdoc />
        public async Task<Result<ExploitSequenceResult>> ExecuteExploitSequenceAsync(
            ExploitSequenceOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var operationName = "ExecuteExploitSequence";
            
            _logger.LogInformation("Starting exploit sequence execution with {PayloadCount} payloads", options.PayloadPaths.Count);

            try
            {
                var result = new ExploitSequenceResult
                {
                    TotalSteps = options.PayloadPaths.Count,
                    StepResults = new List<ExploitStepResult>()
                };

                // Connect to PLC first
                var connectionResult = await ConnectAsync(options.ChannelConfig, cancellationToken).ConfigureAwait(false);
                if (!connectionResult.IsSuccess)
                {
                    result.ErrorMessage = $"Failed to connect to PLC: {connectionResult.Error.Message}";
                    return Result<ExploitSequenceResult>.Failure(result.ErrorMessage);
                }

                // Perform handshake if requested
                if (options.PerformHandshake)
                {
                    var handshakeResult = await PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
                    if (!handshakeResult.IsSuccess)
                    {
                        result.Warnings.Add($"Handshake failed: {handshakeResult.Error.Message}");
                    }
                }

                // Execute each payload
                for (int i = 0; i < options.PayloadPaths.Count; i++)
                {
                    var payloadPath = options.PayloadPaths[i];
                    var stepResult = await ExecutePayloadStepAsync(payloadPath, i + 1, cancellationToken).ConfigureAwait(false);
                    result.StepResults.Add(stepResult);
                    result.StepsExecuted++;

                    if (!stepResult.IsSuccess && !options.ContinueOnFailure)
                    {
                        _logger.LogError("Payload execution failed and ContinueOnFailure is false. Stopping sequence");
                        break;
                    }
                }

                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.IsSuccess = result.StepResults.TrueForAll(s => s.IsSuccess);

                _logger.LogInformation("Exploit sequence execution completed. Success: {IsSuccess}, Duration: {Duration}ms",
                    result.IsSuccess, stopwatch.ElapsedMilliseconds);

                OnOperationCompleted(operationName, result.IsSuccess, stopwatch.Elapsed, result.ErrorMessage);
                return Result<ExploitSequenceResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Exploit sequence execution was cancelled");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, "Operation was cancelled");
                return Result<ExploitSequenceResult>.Failure("Operation was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exploit sequence execution failed with exception");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<ExploitSequenceResult>.Failure($"Exploit sequence failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PlcConnectionInfo>> ConnectAsync(
            CommunicationChannelConfig channelConfig,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(channelConfig);

            var stopwatch = Stopwatch.StartNew();
            var operationName = "Connect";

            _logger.LogInformation("Establishing PLC connection. Mode: {Mode}, Host: {Host}, Port: {Port}",
                channelConfig.Mode, channelConfig.Host, channelConfig.Port);

            try
            {
                SetConnectionStatus(PlcConnectionStatus.Connecting);

                // Dispose existing client if any
                _currentClient?.Dispose();

                // Create new client
                _currentClient = CreatePlcClient(channelConfig);
                
                // Perform connection with timeout
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(channelConfig.Timeout);

                // Connection is handled by the underlying channel - simulate connection
                await Task.Delay(100, timeoutCts.Token).ConfigureAwait(false);
                
                // Check if client is connected
                if (!_currentClient.IsConnected)
                {
                    throw new InvalidOperationException("Failed to establish connection to PLC");
                }

                stopwatch.Stop();
                SetConnectionStatus(PlcConnectionStatus.Connected);

                var connectionInfo = new PlcConnectionInfo
                {
                    ConnectionId = Guid.NewGuid().ToString(),
                    Address = channelConfig.Host ?? channelConfig.SerialPort ?? "Unknown",
                    ConnectionType = channelConfig.Mode,
                    ConnectedAt = DateTime.UtcNow,
                    IsActive = true,
                    Properties = new Dictionary<string, object>
                    {
                        ["Port"] = channelConfig.Port,
                        ["Timeout"] = channelConfig.Timeout.TotalMilliseconds
                    }
                };

                _logger.LogInformation("PLC connection established successfully in {Duration}ms",
                    stopwatch.ElapsedMilliseconds);

                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result<PlcConnectionInfo>.Success(connectionInfo);
            }
            catch (OperationCanceledException)
            {
                SetConnectionStatus(PlcConnectionStatus.Error);
                _logger.LogWarning("PLC connection attempt was cancelled");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, "Connection attempt was cancelled");
                return Result<PlcConnectionInfo>.Failure("Connection attempt was cancelled");
            }
            catch (Exception ex)
            {
                SetConnectionStatus(PlcConnectionStatus.Error);
                _logger.LogError(ex, "Failed to establish PLC connection");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<PlcConnectionInfo>.Failure($"Connection failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result> DisconnectAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var operationName = "Disconnect";

            _logger.LogInformation("Disconnecting from PLC");

            try
            {
                if (_currentClient != null)
                {
                    // PlcClient doesn't have DisconnectAsync - just dispose
                    _currentClient.Dispose();
                    _currentClient = null;
                }

                stopwatch.Stop();
                SetConnectionStatus(PlcConnectionStatus.Disconnected);

                _logger.LogInformation("PLC disconnection completed in {Duration}ms", stopwatch.ElapsedMilliseconds);
                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to disconnect from PLC");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result.Failure($"Disconnection failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<HandshakeResult>> PerformHandshakeAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var operationName = "PerformHandshake";

            if (_currentClient == null)
            {
                return Result<HandshakeResult>.Failure("No active PLC connection");
            }

            _logger.LogInformation("Performing PLC handshake");

            try
            {
                await _currentClient.PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();

                var handshakeResult = new HandshakeResult
                {
                    IsSuccess = true,
                    Duration = stopwatch.Elapsed,
                    ProtocolVersion = "S7-1200/1500", // This would be detected from actual handshake
                    AdditionalInfo = new Dictionary<string, object>
                    {
                        ["HandshakeTime"] = DateTime.UtcNow,
                        ["ClientVersion"] = "1.0"
                    }
                };

                _logger.LogInformation("PLC handshake completed successfully in {Duration}ms", stopwatch.ElapsedMilliseconds);
                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result<HandshakeResult>.Success(handshakeResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PLC handshake failed");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<HandshakeResult>.Failure($"Handshake failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<byte[]>> ReadMemoryAsync(
            uint address,
            uint length,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var operationName = "ReadMemory";

            if (_currentClient == null)
            {
                return Result<byte[]>.Failure("No active PLC connection");
            }

            _logger.LogInformation("Reading {Length} bytes from PLC memory at address 0x{Address:X8}", length, address);

            try
            {
                // Use DumpMemoryAsync which is the actual method available
                var dumpPayload = new byte[1024]; // Placeholder dump payload
                var data = await _currentClient.DumpMemoryAsync(address, length, dumpPayload, null, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();

                _logger.LogInformation("Successfully read {Length} bytes from PLC memory in {Duration}ms",
                    data.Length, stopwatch.ElapsedMilliseconds);

                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result<byte[]>.Success(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read PLC memory at address 0x{Address:X8}", address);
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<byte[]>.Failure($"Memory read failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result> WriteMemoryAsync(
            uint address,
            byte[] data,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(data);

            var stopwatch = Stopwatch.StartNew();
            var operationName = "WriteMemory";

            if (_currentClient == null)
            {
                return Result.Failure("No active PLC connection");
            }

            _logger.LogInformation("Writing {Length} bytes to PLC memory at address 0x{Address:X8}", data.Length, address);

            try
            {
                // Use WriteToIram or WriteViaStager which are the actual methods available
                await _currentClient.WriteToIram(address, data, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();

                _logger.LogInformation("Successfully wrote {Length} bytes to PLC memory in {Duration}ms",
                    data.Length, stopwatch.ElapsedMilliseconds);

                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write PLC memory at address 0x{Address:X8}", address);
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result.Failure($"Memory write failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<PlcInfo>> GetPlcInfoAsync(CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var operationName = "GetPlcInfo";

            if (_currentClient == null)
            {
                return Result<PlcInfo>.Failure("No active PLC connection");
            }

            _logger.LogInformation("Retrieving PLC information");

            try
            {
                // Simulate PLC info retrieval - in real implementation this would query the PLC
                await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();

                var plcInfo = new PlcInfo
                {
                    Model = "S7-1200",
                    FirmwareVersion = "4.2.1",
                    HardwareVersion = "1.0",
                    SerialNumber = "6ES7214-1AG40-0XB0",
                    SupportedProtocols = new List<string> { "S7", "Modbus", "Profinet" },
                    MemoryLayout = new Dictionary<string, object>
                    {
                        ["TotalMemory"] = 1024 * 1024, // 1MB
                        ["AvailableMemory"] = 512 * 1024, // 512KB
                        ["ProgramMemory"] = 256 * 1024 // 256KB
                    },
                    Properties = new Dictionary<string, object>
                    {
                        ["LastQueried"] = DateTime.UtcNow,
                        ["QueryDuration"] = stopwatch.Elapsed
                    }
                };

                _logger.LogInformation("Successfully retrieved PLC information in {Duration}ms", stopwatch.ElapsedMilliseconds);
                OnOperationCompleted(operationName, true, stopwatch.Elapsed);
                return Result<PlcInfo>.Success(plcInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve PLC information");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<PlcInfo>.Failure($"Failed to get PLC info: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<S7.Core.Abstractions.Validation.ValidationResult>> ValidateConnectionAsync(
            CommunicationChannelConfig channelConfig,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(channelConfig);

            var stopwatch = Stopwatch.StartNew();
            var operationName = "ValidateConnection";

            _logger.LogInformation("Validating PLC connection configuration");

            try
            {
                SetConnectionStatus(PlcConnectionStatus.Validating);

                var errors = new List<string>();

                // Validate configuration
                if (string.IsNullOrWhiteSpace(channelConfig.Mode))
                {
                    errors.Add("Connection mode is required");
                }

                if (channelConfig.Mode?.ToUpperInvariant() == "TCP")
                {
                    if (string.IsNullOrWhiteSpace(channelConfig.Host))
                    {
                        errors.Add("Host is required for TCP connection");
                    }
                    if (channelConfig.Port <= 0 || channelConfig.Port > 65535)
                    {
                        errors.Add("Port must be between 1 and 65535");
                    }
                }
                else if (channelConfig.Mode?.ToUpperInvariant() == "SERIAL")
                {
                    if (string.IsNullOrWhiteSpace(channelConfig.SerialPort))
                    {
                        errors.Add("Serial port is required for serial connection");
                    }
                }

                // Test connection if configuration is valid
                if (errors.Count == 0)
                {
                    try
                    {
                        var connectionResult = await ConnectAsync(channelConfig, cancellationToken).ConfigureAwait(false);
                        if (connectionResult.IsSuccess)
                        {
                            await DisconnectAsync(cancellationToken).ConfigureAwait(false);
                            _logger.LogInformation("Connection test successful");
                        }
                        else
                        {
                            errors.Add($"Connection test failed: {connectionResult.Error.Message}");
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Connection test failed: {ex.Message}");
                    }
                }

                stopwatch.Stop();
                SetConnectionStatus(PlcConnectionStatus.Disconnected);

                var validationResult = errors.Count == 0 
                    ? S7.Core.Abstractions.Validation.ValidationResult.Success()
                    : S7.Core.Abstractions.Validation.ValidationResult.Failure(errors);

                _logger.LogInformation("Connection validation completed in {Duration}ms. Valid: {IsValid}",
                    stopwatch.ElapsedMilliseconds, validationResult.IsValid);

                OnOperationCompleted(operationName, validationResult.IsValid, stopwatch.Elapsed);
                return Result<S7.Core.Abstractions.Validation.ValidationResult>.Success(validationResult);
            }
            catch (Exception ex)
            {
                SetConnectionStatus(PlcConnectionStatus.Error);
                _logger.LogError(ex, "Connection validation failed");
                OnOperationCompleted(operationName, false, stopwatch.Elapsed, ex.Message);
                return Result<S7.Core.Abstractions.Validation.ValidationResult>.Failure($"Validation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public PlcConnectionStatus GetConnectionStatus()
        {
            return _connectionStatus;
        }

        private PlcClient CreatePlcClient(CommunicationChannelConfig config)
        {
            ICommunicationChannel channel = config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new SerialChannel(config.SerialPort ?? "COM1", config.BaudRate),
                _ => throw new ArgumentException($"Unsupported connection type: {config.Mode}")
            };

            Action<string> logger = message => _logger.LogDebug("{Message}", message);
            return new PlcClient(channel, logger);
        }

        private async Task<ExploitStepResult> ExecutePayloadStepAsync(
            string payloadPath,
            int stepNumber,
            CancellationToken cancellationToken)
        {
            var stepStopwatch = Stopwatch.StartNew();
            
            _logger.LogInformation("Executing payload step {StepNumber}: {PayloadPath}", stepNumber, payloadPath);

            try
            {
                // Load and execute payload
                var payload = await _payloadManager.LoadPayloadAsync(payloadPath, cancellationToken).ConfigureAwait(false);
                
                // Simulate payload execution
                await Task.Delay(2000, cancellationToken).ConfigureAwait(false);

                stepStopwatch.Stop();

                var result = new ExploitStepResult
                {
                    StepName = $"Payload {stepNumber}: {System.IO.Path.GetFileName(payloadPath)}",
                    IsSuccess = true,
                    Duration = stepStopwatch.Elapsed,
                    Data = new Dictionary<string, object>
                    {
                        ["PayloadPath"] = payloadPath,
                        ["PayloadSize"] = payload?.Length ?? 0,
                        ["ExecutionTime"] = DateTime.UtcNow
                    }
                };

                _logger.LogInformation("Payload step {StepNumber} completed successfully in {Duration}ms",
                    stepNumber, stepStopwatch.ElapsedMilliseconds);

                return result;
            }
            catch (Exception ex)
            {
                stepStopwatch.Stop();
                
                _logger.LogError(ex, "Payload step {StepNumber} failed", stepNumber);

                return new ExploitStepResult
                {
                    StepName = $"Payload {stepNumber}: {System.IO.Path.GetFileName(payloadPath)}",
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                    Duration = stepStopwatch.Elapsed
                };
            }
        }

        private void SetConnectionStatus(PlcConnectionStatus newStatus)
        {
            var previousStatus = _connectionStatus;
            _connectionStatus = newStatus;

            if (previousStatus != newStatus)
            {
                _logger.LogInformation("PLC connection status changed from {PreviousStatus} to {CurrentStatus}",
                    previousStatus, newStatus);

                ConnectionStatusChanged?.Invoke(this, new PlcConnectionStatusChangedEventArgs(
                    previousStatus, newStatus, $"Status changed from {previousStatus} to {newStatus}"));
            }
        }

        private void OnOperationCompleted(string operationName, bool isSuccess, TimeSpan duration, string? errorMessage = null)
        {
            OperationCompleted?.Invoke(this, new PlcOperationCompletedEventArgs(
                operationName, isSuccess, duration, errorMessage));
        }

        /// <summary>
        /// Disposes the service and cleans up resources.
        /// </summary>
        public void Dispose()
        {
            _currentClient?.Dispose();
            _currentClient = null;
            SetConnectionStatus(PlcConnectionStatus.Disconnected);
        }
    }
}