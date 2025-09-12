using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using NModbus;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Controls the power supply of the PLC via Modbus.
    /// </summary>
    public class PowerController
    {
        private readonly Action<string, bool> _log;

        /// <summary>
        /// Initializes a new instance of the <see cref="PowerController"/> class.
        /// </summary>
        /// <param name="logger">The logging action.</param>
        public PowerController(Action<string, bool> logger)
        {
            _log = logger;
        }

        /// <summary>
        /// Sets the power of the PLC.
        /// </summary>
        /// <param name="host">The Modbus host.</param>
        /// <param name="port">The Modbus port.</param>
        /// <param name="coilAddress">The coil address to write to.</param>
        /// <param name="on">True to turn the power on, false to turn it off.</param>
        /// <param name="slaveId">The slave ID of the Modbus device.</param>
        public async Task SetPowerAsync(string host, int port, ushort coilAddress, bool on, byte slaveId = 1)
        {
            string state = on ? "ON" : "OFF";
            _log($"Attempting to turn power {state}...", false);

            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(host, port);
                    if (!client.Connected)
                    {
                        _log($"Error: Could not connect to Modbus host {host}:{port}.", true);
                        return;
                    }

                    var factory = new ModbusFactory();
                    IModbusMaster master = factory.CreateMaster(client);

                    ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);

                    await master.WriteSingleCoilAsync(slaveId, zeroBasedCoilAddress, on);
                    _log($"Successfully turned power {state}.", false);
                }
            }
            catch (Exception ex)
            {
                _log($"Error controlling power: {ex.Message}", true);
            }
        }
    }
}
