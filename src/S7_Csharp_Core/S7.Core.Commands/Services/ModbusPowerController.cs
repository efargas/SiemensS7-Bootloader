using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NModbus;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Services;

namespace S7.Core.Commands.Services
{
    /// <summary>
    /// Modbus-based power controller implementation.
    /// </summary>
    public class ModbusPowerController : IPowerController, IDisposable
    {
        private readonly ILogger<ModbusPowerController> _logger;
        private readonly ModbusConnectionManager _connectionManager;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the ModbusPowerController class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="connectionManager">The Modbus connection manager</param>
        public ModbusPowerController(
            ILogger<ModbusPowerController> logger,
            ModbusConnectionManager connectionManager)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectionManager = connectionManager ?? throw new ArgumentNullException(nameof(connectionManager));
        }

        /// <summary>
        /// Performs a power cycle operation (turn off, wait, turn on).
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power cycle operation</returns>
        public async Task PowerCycleAsync(PowerControllerConfig config, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(config);
            ThrowIfDisposed();

            _logger.LogInformation("Starting power cycle operation. Host: {Host}, Port: {Port}, Coil: {Coil}",
                config.Host, config.Port, config.Coil);

            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Turn power OFF
                await SetPowerAsync(config, false, cancellationToken);

                // Wait for the specified delay
                if (config.DelaySeconds > 0)
                {
                    _logger.LogInformation("Waiting {DelaySeconds} seconds before turning power back on", config.DelaySeconds);
                    await Task.Delay(TimeSpan.FromSeconds(config.DelaySeconds), cancellationToken);
                }

                // Turn power ON
                await SetPowerAsync(config, true, cancellationToken);

                stopwatch.Stop();
                _logger.LogInformation("Power cycle completed successfully in {Duration}ms", stopwatch.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Power cycle operation failed after {Duration}ms", stopwatch.ElapsedMilliseconds);
                throw;
            }
        }

        /// <summary>
        /// Sets the power state of the controlled device.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="powerOn">True to turn power on, false to turn power off</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power control operation</returns>
        public async Task SetPowerAsync(PowerControllerConfig config, bool powerOn, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(config);
            ThrowIfDisposed();

            _logger.LogInformation("Setting power state to {PowerState}. Host: {Host}, Port: {Port}, Coil: {Coil}",
                powerOn ? "ON" : "OFF", config.Host, config.Port, config.Coil);

            var attempt = 0;
            var stopwatch = Stopwatch.StartNew();

            while (attempt <= config.RetryAttempts)
            {
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeoutCts.CancelAfter(config.Timeout);

                    var connection = await _connectionManager.GetConnectionAsync(config.Host, config.Port, timeoutCts.Token);
                    
                    // Write to the coil
                    await connection.WriteSingleCoilAsync(1, (ushort)config.Coil, powerOn);

                    stopwatch.Stop();
                    _logger.LogInformation("Power state set to {PowerState} successfully in {Duration}ms (attempt {Attempt})",
                        powerOn ? "ON" : "OFF", stopwatch.ElapsedMilliseconds, attempt + 1);
                    return;
                }
                catch (Exception ex) when (attempt < config.RetryAttempts && !cancellationToken.IsCancellationRequested)
                {
                    attempt++;
                    _logger.LogWarning(ex, "Power control attempt {Attempt} failed, retrying in {Delay}ms",
                        attempt, config.RetryDelay.TotalMilliseconds);
                    
                    await Task.Delay(config.RetryDelay, cancellationToken);
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    _logger.LogError(ex, "Power control operation failed after {Attempts} attempts and {Duration}ms",
                        attempt + 1, stopwatch.ElapsedMilliseconds);
                    throw;
                }
            }
        }

        /// <summary>
        /// Gets the current power status of the controlled device.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the power status check, returning true if power is on</returns>
        public async Task<bool> GetPowerStatusAsync(PowerControllerConfig config, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(config);
            ThrowIfDisposed();

            _logger.LogDebug("Getting power status. Host: {Host}, Port: {Port}, Coil: {Coil}",
                config.Host, config.Port, config.Coil);

            var stopwatch = Stopwatch.StartNew();

            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(config.Timeout);

                var connection = await _connectionManager.GetConnectionAsync(config.Host, config.Port, timeoutCts.Token);
                
                // Read the coil status
                var coilStatus = await connection.ReadCoilsAsync(1, (ushort)config.Coil, 1);
                var powerState = coilStatus[0];

                stopwatch.Stop();
                _logger.LogDebug("Power status retrieved: {PowerState} in {Duration}ms",
                    powerState ? "ON" : "OFF", stopwatch.ElapsedMilliseconds);

                return powerState;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Failed to get power status after {Duration}ms", stopwatch.ElapsedMilliseconds);
                throw;
            }
        }

        /// <summary>
        /// Tests the connection to the power controller.
        /// </summary>
        /// <param name="config">The power controller configuration</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the connection test, returning true if connection is successful</returns>
        public async Task<bool> TestConnectionAsync(PowerControllerConfig config, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(config);
            ThrowIfDisposed();

            _logger.LogInformation("Testing connection to power controller. Host: {Host}, Port: {Port}",
                config.Host, config.Port);

            var stopwatch = Stopwatch.StartNew();

            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(config.Timeout);

                var connection = await _connectionManager.GetConnectionAsync(config.Host, config.Port, timeoutCts.Token);
                
                // Try to read a single coil to test the connection
                await connection.ReadCoilsAsync(1, (ushort)config.Coil, 1);

                stopwatch.Stop();
                _logger.LogInformation("Connection test successful in {Duration}ms", stopwatch.ElapsedMilliseconds);
                return true;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogWarning(ex, "Connection test failed after {Duration}ms", stopwatch.ElapsedMilliseconds);
                return false;
            }
        }

        /// <summary>
        /// Disposes the power controller and releases resources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _connectionManager?.Dispose();
                _disposed = true;
                _logger.LogDebug("ModbusPowerController disposed");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ModbusPowerController));
        }
    }

    /// <summary>
    /// Manages Modbus connections with connection pooling and reuse.
    /// </summary>
    public class ModbusConnectionManager : IDisposable
    {
        private readonly ILogger<ModbusConnectionManager> _logger;
        private readonly Dictionary<string, IModbusMaster> _connections;
        private readonly object _lock = new object();
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the ModbusConnectionManager class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        public ModbusConnectionManager(ILogger<ModbusConnectionManager> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connections = new Dictionary<string, IModbusMaster>();
        }

        /// <summary>
        /// Gets a Modbus connection for the specified host and port.
        /// </summary>
        /// <param name="host">The Modbus host address</param>
        /// <param name="port">The Modbus port number</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the connection operation</returns>
        public async Task<IModbusMaster> GetConnectionAsync(string host, int port, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(host);
            ThrowIfDisposed();

            var connectionKey = $"{host}:{port}";

            lock (_lock)
            {
                if (_connections.TryGetValue(connectionKey, out var existingConnection))
                {
                    _logger.LogDebug("Reusing existing Modbus connection to {ConnectionKey}", connectionKey);
                    return existingConnection;
                }
            }

            _logger.LogInformation("Creating new Modbus connection to {ConnectionKey}", connectionKey);

            try
            {
                // Create a new TCP Modbus connection
                var factory = new ModbusFactory();
                var tcpClient = new System.Net.Sockets.TcpClient();
                
                await tcpClient.ConnectAsync(host, port, cancellationToken);
                var connection = factory.CreateMaster(tcpClient);

                lock (_lock)
                {
                    _connections[connectionKey] = connection;
                }

                _logger.LogInformation("Modbus connection to {ConnectionKey} established successfully", connectionKey);
                return connection;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create Modbus connection to {ConnectionKey}", connectionKey);
                throw;
            }
        }

        /// <summary>
        /// Disposes all connections and releases resources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                lock (_lock)
                {
                    foreach (var connection in _connections.Values)
                    {
                        try
                        {
                            connection?.Dispose();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Error disposing Modbus connection");
                        }
                    }
                    _connections.Clear();
                }

                _disposed = true;
                _logger.LogDebug("ModbusConnectionManager disposed");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ModbusConnectionManager));
        }
    }
}