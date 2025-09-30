using S7.Net.Interfaces;
using System.IO.Ports;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Channels
{
    /// <summary>
    /// A communication channel that uses a serial port.
    /// </summary>
    public class SerialChannel : ICommunicationChannel
    {
        private readonly string _portName;
        private readonly int _baudRate;
        private readonly Parity _parity;
        private readonly StopBits _stopBits;
        private readonly Handshake _handshake;
        private SerialPort? _serialPort;

        /// <summary>
        /// Indicates whether the channel is connected.
        /// </summary>
        public bool IsConnected => _serialPort?.IsOpen ?? false;
        /// <summary>
        /// Indicates whether there is data available to be read.
        /// </summary>
        public bool DataAvailable => (_serialPort?.BytesToRead ?? 0) > 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="SerialChannel"/> class.
        /// </summary>
        /// <param name="portName">The name of the serial port.</param>
        /// <param name="baudRate">The baud rate.</param>
        /// <param name="parity">The parity.</param>
        /// <param name="stopBits">The stop bits.</param>
        /// <param name="handshake">The handshake.</param>
        public SerialChannel(string portName, int baudRate, Parity parity, StopBits stopBits, Handshake handshake)
        {
            _portName = portName;
            _baudRate = baudRate;
            _parity = parity;
            _stopBits = stopBits;
            _handshake = handshake;
        }

        /// <summary>
        /// Connects to the serial port.
        /// </summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            if (IsConnected) Disconnect();
            _serialPort = new SerialPort(_portName, _baudRate, _parity, 8, _stopBits)
            {
                Handshake = _handshake
            };
            _serialPort.Open();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Disconnects from the serial port.
        /// </summary>
        public void Disconnect()
        {
            _serialPort?.Close();
            _serialPort = null;
        }

        /// <summary>
        /// Reads data from the serial port.
        /// </summary>
        /// <param name="buffer">The buffer to read data into.</param>
        /// <param name="offset">The offset in the buffer to start writing to.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of bytes read.</returns>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            return await _serialPort.BaseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Writes data to the serial port.
        /// </summary>
        /// <param name="buffer">The buffer containing the data to write.</param>
        /// <param name="offset">The offset in the buffer to start writing from.</param>
        /// <param name="count">The number of bytes to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            await _serialPort.BaseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }
    }
}
