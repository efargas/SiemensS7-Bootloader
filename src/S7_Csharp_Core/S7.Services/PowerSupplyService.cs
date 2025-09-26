using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for power supply operations using Modbus protocol.
    /// </summary>
    public class PowerSupplyService(
        IPowerController powerController,
        ILogger<PowerSupplyService> logger) : IPowerSupplyService
    {
        private readonly IPowerController _powerController = powerController ?? throw new ArgumentNullException(nameof(powerController));
        private readonly ILogger<PowerSupplyService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        private PowerSupplyConnectionStatus _connectionStatus = PowerSupplyConnectionStatus.Disconnected;
        private PowerSupplyConfig? _currentConfig;
        private readonly object _statusLock = new();

        /// <inheritdoc />
        public PowerSupplyConnectionStatus ConnectionStatus
        {
            get
            {
                lock (_statusLock)
                {
                    return _connectionStatus;
                }
            }
            private set
            {
                PowerSupplyConnectionStatus previousStatus;
                lock (_statusLock)
                {
                    previousStatus = _connectionStatus;
                    _connectionStatus = value;
                }
                
                if (previousStatus != value)
                {
                    _logger.LogInformation("Power supply connection status changed from {PreviousStatus} to {CurrentStatus}", 
                        previousStatus, value);
                    ConnectionStatusChanged?.Invoke(this, new PowerSupplyConnectionStatusChangedEventArgs(previousStatus, value));
                }
            }
        }

        /// <inheritdoc />
        public bool IsConnected => ConnectionStatus == PowerSupplyConnectionStatus.Connected;

        /// <inheritdoc />
        public PowerSupplyConfig? CurrentConfig => _currentConfig;

        /// <inheritdoc />
        public event EventHandler<PowerSupplyConnectionStatusChangedEventArgs>? ConnectionStatusChanged;

        /// <inheritdoc />
        public event EventHandler<PowerStateChangedEventArgs>? PowerStateChanged;

        /// <inheritdoc />
        public async Task<bool> ConnectAsync(PowerSupplyConfig config, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(config);
            
            _logger.LogInformation("Attempting to connect to power supply at {Host}:{Port} with slave ID {SlaveId}", 
                config.Host, config.Port, config.SlaveId);

            if (ConnectionStatus == PowerSupplyConnectionStatus.Connected)
            {
                _logger.LogWarning("Already connected to power supply. Disconnecting first.");
                await DisconnectAsync();
            }

            ConnectionStatus = PowerSupplyConnectionStatus.Connecting;
            _currentConfig = config;

            try
            {
                using var timeoutCts = new CancellationTokenSource(config.ConnectionTimeout);
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                var stopwatch = Stopwatch.StartNew();
                
                await _powerController.ConnectAsync(config.Host, config.Port);
                
                stopwatch.Stop();
                
                if (_powerController.IsConnected)
                {
                    ConnectionStatus = PowerSupplyConnectionStatus.Connected;
                    _logger.LogInformation("Successfully connected to power supply in {Duration}ms", stopwatch.ElapsedMilliseconds);
                    return true;
                }
                else
                {
                    ConnectionStatus = PowerSupplyConnectionStatus.Error;
                    _logger.LogError("Failed to connect to power supply - connection not established");
                    return false;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                ConnectionStatus = PowerSupplyConnectionStatus.Disconnected;
                _logger.LogWarning("Power supply connection was cancelled by user");
                throw;
            }
            catch (OperationCanceledException)
            {
                ConnectionStatus = PowerSupplyConnectionStatus.Error;
                _logger.LogError("Power supply connection timed out after {Timeout}ms", config.ConnectionTimeout.TotalMilliseconds);
                return false;
            }
            catch (Exception ex)
            {
                ConnectionStatus = PowerSupplyConnectionStatus.Error;
                _logger.LogError(ex, "Failed to connect to power supply at {Host}:{Port}", config.Host, config.Port);
                return false;
            }
        }

        /// <inheritdoc />
        public async Task DisconnectAsync()
        {
            if (ConnectionStatus == PowerSupplyConnectionStatus.Disconnected)
            {
                _logger.LogDebug("Power supply is already disconnected");
                return;
            }

            _logger.LogInformation("Disconnecting from power supply");

            try
            {
                await Task.Run(() => _powerController.Disconnect());
                ConnectionStatus = PowerSupplyConnectionStatus.Disconnected;
                _currentConfig = null;
                _logger.LogInformation("Successfully disconnected from power supply");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while disconnecting from power supply");
                ConnectionStatus = PowerSupplyConnectionStatus.Error;
                throw;
            }
        }

        /// <inheritdoc />
        public async Task<PowerOperationResult> SetPowerAsync(ushort coilAddress, bool powerOn, CancellationToken cancellationToken = default)
        {
            if (!IsConnected)
            {
                const string errorMessage = "Cannot set power: Power supply is not connected";
                _logger.LogError(errorMessage);
                return PowerOperationResult.Failure(errorMessage, PowerState.Unknown, TimeSpan.Zero);
            }

            if (_currentConfig == null)
            {
                const string errorMessage = "Cannot set power: No configuration available";
                _logger.LogError(errorMessage);
                return PowerOperationResult.Failure(errorMessage, PowerState.Unknown, TimeSpan.Zero);
            }

            _logger.LogInformation("Setting power {PowerState} for coil {CoilAddress}", powerOn ? "ON" : "OFF", coilAddress);

            var stopwatch = Stopwatch.StartNew();
            var previousState = await GetPowerStateAsync(coilAddress, cancellationToken);

            try
            {
                using var timeoutCts = new CancellationTokenSource(_currentConfig.OperationTimeout);
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                await _powerController.SetPowerAsync(coilAddress, powerOn, _currentConfig.SlaveId);
                
                stopwatch.Stop();
                
                // Verify the power state was set correctly
                var finalState = await GetPowerStateAsync(coilAddress, cancellationToken);
                var expectedState = powerOn ? PowerState.On : PowerState.Off;
                
                if (finalState == expectedState)
                {
                    _logger.LogInformation("Successfully set power {PowerState} for coil {CoilAddress} in {Duration}ms", 
                        powerOn ? "ON" : "OFF", coilAddress, stopwatch.ElapsedMilliseconds);
                    
                    // Raise power state changed event
                    PowerStateChanged?.Invoke(this, new PowerStateChangedEventArgs(previousState, finalState, coilAddress));
                    
                    return PowerOperationResult.Success(finalState, stopwatch.Elapsed);
                }
                else
                {
                    var errorMessage = $"Power state verification failed. Expected: {expectedState}, Actual: {finalState}";
                    _logger.LogError(errorMessage);
                    return PowerOperationResult.Failure(errorMessage, finalState, stopwatch.Elapsed);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                _logger.LogWarning("Power operation was cancelled by user");
                throw;
            }
            catch (OperationCanceledException)
            {
                stopwatch.Stop();
                var errorMessage = $"Power operation timed out after {_currentConfig.OperationTimeout.TotalMilliseconds}ms";
                _logger.LogError(errorMessage);
                return PowerOperationResult.Failure(errorMessage, PowerState.Unknown, stopwatch.Elapsed);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Failed to set power {PowerState} for coil {CoilAddress}", powerOn ? "ON" : "OFF", coilAddress);
                return PowerOperationResult.Failure(ex.Message, PowerState.Unknown, stopwatch.Elapsed);
            }
        }

        /// <inheritdoc />
        public async Task<PowerState> GetPowerStateAsync(ushort coilAddress, CancellationToken cancellationToken = default)
        {
            if (!IsConnected)
            {
                _logger.LogWarning("Cannot get power state: Power supply is not connected");
                return PowerState.Unknown;
            }

            try
            {
                // Note: The current PowerController doesn't have a method to read coil state
                // This is a limitation of the current implementation
                // For now, we'll return Unknown and log this limitation
                _logger.LogDebug("Getting power state for coil {CoilAddress} - current implementation limitation", coilAddress);
                return PowerState.Unknown;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get power state for coil {CoilAddress}", coilAddress);
                return PowerState.Unknown;
            }
        }

        /// <inheritdoc />
        public async Task<PowerOperationResult> PowerCycleAsync(ushort coilAddress, TimeSpan delayBetweenStates, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting power cycle for coil {CoilAddress} with {Delay}ms delay", 
                coilAddress, delayBetweenStates.TotalMilliseconds);

            var totalStopwatch = Stopwatch.StartNew();

            try
            {
                // Step 1: Turn power OFF
                _logger.LogDebug("Power cycle step 1: Turning power OFF");
                var powerOffResult = await SetPowerAsync(coilAddress, false, cancellationToken);
                if (!powerOffResult.IsSuccess)
                {
                    totalStopwatch.Stop();
                    _logger.LogError("Power cycle failed at step 1 (power OFF): {Error}", powerOffResult.ErrorMessage);
                    return PowerOperationResult.Failure($"Failed to turn power OFF: {powerOffResult.ErrorMessage}", 
                        powerOffResult.FinalState, totalStopwatch.Elapsed);
                }

                // Step 2: Wait for the specified delay
                _logger.LogDebug("Power cycle step 2: Waiting {Delay}ms", delayBetweenStates.TotalMilliseconds);
                await Task.Delay(delayBetweenStates, cancellationToken);

                // Step 3: Turn power ON
                _logger.LogDebug("Power cycle step 3: Turning power ON");
                var powerOnResult = await SetPowerAsync(coilAddress, true, cancellationToken);
                if (!powerOnResult.IsSuccess)
                {
                    totalStopwatch.Stop();
                    _logger.LogError("Power cycle failed at step 3 (power ON): {Error}", powerOnResult.ErrorMessage);
                    return PowerOperationResult.Failure($"Failed to turn power ON: {powerOnResult.ErrorMessage}", 
                        powerOnResult.FinalState, totalStopwatch.Elapsed);
                }

                totalStopwatch.Stop();
                _logger.LogInformation("Power cycle completed successfully for coil {CoilAddress} in {Duration}ms", 
                    coilAddress, totalStopwatch.ElapsedMilliseconds);

                return PowerOperationResult.Success(powerOnResult.FinalState, totalStopwatch.Elapsed);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                totalStopwatch.Stop();
                _logger.LogWarning("Power cycle was cancelled by user");
                throw;
            }
            catch (Exception ex)
            {
                totalStopwatch.Stop();
                _logger.LogError(ex, "Unexpected error during power cycle for coil {CoilAddress}", coilAddress);
                return PowerOperationResult.Failure($"Unexpected error during power cycle: {ex.Message}", 
                    PowerState.Unknown, totalStopwatch.Elapsed);
            }
        }

        /// <inheritdoc />
        public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            if (!IsConnected)
            {
                _logger.LogWarning("Cannot test connection: Power supply is not connected");
                return false;
            }

            _logger.LogDebug("Testing power supply connection");

            try
            {
                // Test connection by attempting to read a coil state
                // Since we don't have a read method, we'll just check if the controller is still connected
                await Task.Run(() => _powerController.IsConnected, cancellationToken);
                
                var isConnected = _powerController.IsConnected;
                _logger.LogDebug("Connection test result: {IsConnected}", isConnected);
                
                if (!isConnected)
                {
                    ConnectionStatus = PowerSupplyConnectionStatus.Error;
                }
                
                return isConnected;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Connection test failed");
                ConnectionStatus = PowerSupplyConnectionStatus.Error;
                return false;
            }
        }

        /// <inheritdoc />
        public async Task<string> GetDiagnosticInfoAsync(CancellationToken cancellationToken = default)
        {
            var diagnostics = new System.Text.StringBuilder();
            
            diagnostics.AppendLine("=== Power Supply Service Diagnostics ===");
            diagnostics.AppendLine($"Connection Status: {ConnectionStatus}");
            diagnostics.AppendLine($"Is Connected: {IsConnected}");
            
            if (_currentConfig != null)
            {
                diagnostics.AppendLine($"Host: {_currentConfig.Host}");
                diagnostics.AppendLine($"Port: {_currentConfig.Port}");
                diagnostics.AppendLine($"Slave ID: {_currentConfig.SlaveId}");
                diagnostics.AppendLine($"Coil Address: {_currentConfig.CoilAddress}");
                diagnostics.AppendLine($"Connection Timeout: {_currentConfig.ConnectionTimeout.TotalMilliseconds}ms");
                diagnostics.AppendLine($"Operation Timeout: {_currentConfig.OperationTimeout.TotalMilliseconds}ms");
            }
            else
            {
                diagnostics.AppendLine("Configuration: Not available");
            }

            diagnostics.AppendLine($"PowerController IsConnected: {_powerController.IsConnected}");
            
            // Test connection if connected
            if (IsConnected)
            {
                try
                {
                    var connectionTest = await TestConnectionAsync(cancellationToken);
                    diagnostics.AppendLine($"Connection Test: {(connectionTest ? "PASS" : "FAIL")}");
                }
                catch (Exception ex)
                {
                    diagnostics.AppendLine($"Connection Test: ERROR - {ex.Message}");
                }
            }

            diagnostics.AppendLine("=== End Diagnostics ===");
            
            return diagnostics.ToString();
        }
    }
}