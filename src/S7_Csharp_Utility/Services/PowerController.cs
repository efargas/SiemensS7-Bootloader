using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NModbus;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Controls the power supply of the PLC via Modbus.
    /// </summary>
    public class PowerController : IDisposable
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

        public async Task ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
        {
            if (IsConnected) return;
            try
            {
                _log($"Connecting to Modbus host {host}:{port}...", false);
                _client = new TcpClient();
                await _client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);

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

        public void Dispose()
        {
            _master?.Dispose();
            _client?.Dispose();
            _master = null;
            _client = null;
        }
    }
}
