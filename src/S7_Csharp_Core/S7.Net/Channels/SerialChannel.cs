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
        private bool _disposed;

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
            if (_serialPort != null)
            {
                _serialPort.Close();
                _serialPort = null;
            }
        }

        /// <summary>
        /// Reads data from the serial port.
        /// </summary>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            return await _serialPort.BaseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Writes data to the serial port.
        /// </summary>
        public async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_serialPort == null) throw new System.IO.IOException("Not connected.");
            await _serialPort.BaseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Disposes the channel resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            System.GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes the channel resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from a finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed state (managed objects).
                _serialPort?.Dispose();
            }

            _disposed = true;
        }
    }
}