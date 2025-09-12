using S7.Net.Interfaces;
using System.IO.Ports;
using System.Threading.Tasks;

namespace S7.Net.Channels
{
    public class SerialChannel : ICommunicationChannel
    {
        private readonly string _portName;
        private readonly int _baudRate;
        private readonly Parity _parity;
        private readonly StopBits _stopBits;
        private readonly Handshake _handshake;
        private SerialPort? _serialPort;

        public bool IsConnected => _serialPort?.IsOpen ?? false;
        public bool DataAvailable => (_serialPort?.BytesToRead ?? 0) > 0;

        public SerialChannel(string portName, int baudRate, Parity parity, StopBits stopBits, Handshake handshake)
        {
            _portName = portName;
            _baudRate = baudRate;
            _parity = parity;
            _stopBits = stopBits;
            _handshake = handshake;
        }

        public Task ConnectAsync()
        {
            if (IsConnected) Disconnect();
            _serialPort = new SerialPort(_portName, _baudRate, _parity, 8, _stopBits)
            {
                Handshake = _handshake
            };
            _serialPort.Open();
            return Task.CompletedTask;
        }

        public void Disconnect()
        {
            _serialPort?.Close();
            _serialPort = null;
        }

        public async Task<int> ReadAsync(byte[] buffer, int offset, int count)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            return await _serialPort.BaseStream.ReadAsync(buffer, offset, count);
        }

        public async Task WriteAsync(byte[] buffer, int offset, int count)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            await _serialPort.BaseStream.WriteAsync(buffer, offset, count);
        }
    }
}
