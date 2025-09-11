using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using NModbus;

namespace S7_Csharp_Utility.Services
{
    public class PowerController
    {
        private readonly Action<string, bool> _log;

        public PowerController(Action<string, bool> logger)
        {
            _log = logger;
        }

        public async Task SetPowerAsync(string host, int port, ushort coilAddress, bool on)
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

                    await master.WriteSingleCoilAsync(0, zeroBasedCoilAddress, on);
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
