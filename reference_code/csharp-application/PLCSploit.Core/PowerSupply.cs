using System;
using System.Net.Sockets;
using NModbus;

namespace PLCSploit.Core
{
    public class PowerSupply : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private TcpClient? _tcpClient;
        private IModbusMaster? _modbusMaster;
        private Action<string, LogCategory> _logger;

        public bool IsConnected => _modbusMaster != null && _tcpClient?.Connected == true;

        public PowerSupply(string host, int port, Action<string, LogCategory>? logger = null)
        {
            _host = host;
            _port = port;
            _logger = logger ?? ((msg, cat) => Log.Add(msg, cat));
        }

        public void Connect()
        {
            if (IsConnected) return;
            _logger("Connecting to Modbus power supply...", LogCategory.Communication);
            _tcpClient = new TcpClient(_host, _port);
            var factory = new ModbusFactory();
            _modbusMaster = factory.CreateMaster(_tcpClient);
            _logger("Modbus client created and connected.", LogCategory.Info);
        }

        public void Disconnect()
        {
            if (!IsConnected) return;
            _logger("Disconnecting from Modbus power supply...", LogCategory.Communication);
            _modbusMaster?.Dispose();
            _tcpClient?.Close();
            _modbusMaster = null;
            _tcpClient = null;
            _logger("Modbus client disposed.", LogCategory.Info);
        }

        public void TurnOff()
        {
            if (!IsConnected)
            {
                Connect();
            }
            _logger("Turning off power supply.", LogCategory.Communication);
            _modbusMaster!.WriteSingleCoil(1, 0, false);
            _logger("Power supply turned off.", LogCategory.Info);
        }

        public void TurnOn()
        {
            if (!IsConnected)
            {
                Connect();
            }
            _logger("Turning on power supply.", LogCategory.Communication);
            _modbusMaster!.WriteSingleCoil(1, 0, true);
            _logger("Power supply turned on.", LogCategory.Info);
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
