using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NModbus;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Controls the power supply of the PLC via Modbus.
    /// </summary>
    public class PowerController : IPowerController, IDisposable
    {
        private readonly Action<string, bool> _log;
        private TcpClient? _client;
        private IModbusMaster? _master;

        public bool IsConnected => _client?.Connected ?? false;

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerController"/> class.
        /// </summary>
        /// <param name="logger">The logging action.</param>
        public PowerController(Action<string, bool> logger)
        {
            _log = logger;
        }

        public async Task ConnectAsync(string host, int port)
        {
            if (IsConnected) return;
            try
            {
                _log($"Connecting to Modbus host {host}:{port}...", false);
                _client = new TcpClient();
                await _client.ConnectAsync(host, port).ConfigureAwait(false);

                if (_client.Connected)
                {
                    var factory = new ModbusFactory();
                    _master = factory.CreateMaster(_client);
                    _log("Successfully connected to Modbus host.", false);
                }
                else
                {
                    Dispose();
                    _log($"Error: Could not connect to Modbus host {host}:{port}.", true);
                }
            }
            catch (Exception ex)
            {
                Dispose();
                _log($"Error connecting to Modbus host: {ex.Message}", true);
                throw;
            }
        }

        public void Disconnect()
        {
            if (!IsConnected) return;
            _log("Disconnecting from Modbus host...", false);
            Dispose();
            _log("Successfully disconnected.", false);
        }

        /// <summary>
        /// Sets the power of the PLC.
        /// </summary>
        /// <param name="coilAddress">The coil address to write to.</param>
        /// <param name="on">True to turn the power on, false to turn it off.</param>
        /// <param name="slaveId">The slave ID of the Modbus device.</param>
        public async Task SetPowerAsync(ushort coilAddress, bool on, byte slaveId = 1)
        {
            if (!IsConnected || _master == null)
            {
                _log("Error: Not connected to Modbus host. Please connect first.", true);
                return;
            }

            string state = on ? "ON" : "OFF";
            try
            {
                ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);
                await _master.WriteSingleCoilAsync(slaveId, zeroBasedCoilAddress, on).ConfigureAwait(false);
                _log($"Successfully turned power {state}.", false);
            }
            catch (Exception ex)
            {
                _log($"Error controlling power: {ex.Message}", true);
                Disconnect(); // Disconnect on error
            }
        }

        /// <summary>
        /// Performs a power cycle operation using the specified configuration.
        /// </summary>
        /// <param name="powerConfig">The power controller configuration.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task PowerCycleAsync(PowerControllerConfig powerConfig, CancellationToken cancellationToken = default)
        {
            if (!IsConnected)
            {
                await ConnectAsync(powerConfig.Host ?? "localhost", powerConfig.Port).ConfigureAwait(false);
            }

            _log("Starting power cycle operation...", false);
            
            try
            {
                // Turn power OFF
                await SetPowerAsync(powerConfig.CoilAddress, false, powerConfig.SlaveId).ConfigureAwait(false);
                _log($"Power turned OFF, waiting {powerConfig.OffDelayMs}ms...", false);
                
                // Wait for off delay
                await Task.Delay(powerConfig.OffDelayMs, cancellationToken).ConfigureAwait(false);
                
                // Turn power ON
                await SetPowerAsync(powerConfig.CoilAddress, true, powerConfig.SlaveId).ConfigureAwait(false);
                _log($"Power turned ON, waiting {powerConfig.OnDelayMs}ms...", false);
                
                // Wait for on delay
                await Task.Delay(powerConfig.OnDelayMs, cancellationToken).ConfigureAwait(false);
                
                _log("Power cycle operation completed successfully.", false);
            }
            catch (Exception ex)
            {
                _log($"Error during power cycle operation: {ex.Message}", true);
                throw;
            }
        }

        public void Dispose()
        {
            _master?.Dispose();
            _client?.Dispose();
            _master = null;
            _client = null;
        }
    }
}
