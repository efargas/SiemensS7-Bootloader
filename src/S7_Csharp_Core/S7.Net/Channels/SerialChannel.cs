using S7.Net.Interfaces;
using System;
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
        public bool IsConnected => !_disposed && _serialPort?.IsOpen == true;

        /// <summary>
        /// Indicates whether there is data available to be read.
        /// </summary>
        public bool DataAvailable => !_disposed && (_serialPort?.BytesToRead ?? 0) > 0;

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
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
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
            Dispose();
        }

        /// <summary>
        /// Reads data from the serial port.
        /// </summary>
        public Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            if (_serialPort == null) throw new System.IO.IOException("Channel is not connected.");
            return _serialPort.BaseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Writes data to the serial port.
        /// </summary>
        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            if (_serialPort == null) throw new System.IO.IOException("Channel is not connected.");
            return _serialPort.BaseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Disposes the underlying serial port.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes the managed and unmanaged resources.
        /// </summary>
        /// <param name="disposing">True to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _serialPort?.Dispose();
            }

            _serialPort = null;
            _disposed = true;
        }

        /// <summary>
        /// Finalizer for the SerialChannel.
        /// </summary>
        ~SerialChannel()
        {
            Dispose(false);
        }
    }
}