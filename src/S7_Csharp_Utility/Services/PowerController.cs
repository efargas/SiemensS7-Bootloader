using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NModbus;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Controls the power supply of the PLC via Modbus.
    /// </summary>
    public class PowerController : IDisposable
    {
        private readonly ILogger<PowerController> _logger;
        private TcpClient? _client;
        private IModbusMaster? _master;

        public bool IsConnected => _client?.Connected ?? false;

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerController"/> class.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        public PowerController(ILogger<PowerController> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
        {
            if (IsConnected) return;
            try
            {
                _logger.LogInformation("Connecting to Modbus host {Host}:{Port}...", host, port);
                _client = new TcpClient();
                await _client.ConnectAsync(host, port, cancellationToken);

                if (_client.Connected)
                {
                    var factory = new ModbusFactory();
                    _master = factory.CreateMaster(_client);
                    _logger.LogInformation("Successfully connected to Modbus host.");
                }
                else
                {
                    Dispose();
                    _logger.LogError("Could not connect to Modbus host {Host}:{Port}.", host, port);
                }
            }
            catch (Exception ex)
            {
                Dispose();
                _logger.LogError(ex, "Error connecting to Modbus host.");
                throw;
            }
        }

        public void Disconnect()
        {
            if (!IsConnected) return;
            _logger.LogInformation("Disconnecting from Modbus host...");
            Dispose();
            _logger.LogInformation("Successfully disconnected.");
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
                _logger.LogError("Not connected to Modbus host. Please connect first.");
                throw new InvalidOperationException("Not connected to Modbus host.");
            }

            string state = on ? "ON" : "OFF";
            try
            {
                ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);
                await _master.WriteSingleCoilAsync(slaveId, zeroBasedCoilAddress, on);
                _logger.LogInformation("Successfully turned power {State} for coil {CoilAddress}.", state, coilAddress);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error controlling power for coil {CoilAddress}.", coilAddress);
                Disconnect(); // Disconnect on error
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