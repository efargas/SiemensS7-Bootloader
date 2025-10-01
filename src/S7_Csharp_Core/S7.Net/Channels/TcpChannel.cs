using S7.Net.Interfaces;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Channels
{
    /// <summary>
    /// A communication channel that uses TCP.
    /// </summary>
    public class TcpChannel : ICommunicationChannel
    {
        private readonly string _host;
        private readonly int _port;
        private TcpClient? _client;
        private NetworkStream? _stream;
        private bool _disposed;

        /// <summary>
        /// Indicates whether the channel is connected.
        /// </summary>
        public bool IsConnected => !_disposed && _client?.Connected == true;

        /// <summary>
        /// Indicates whether there is data available to be read.
        /// </summary>
        public bool DataAvailable => !_disposed && _stream?.DataAvailable == true;

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpChannel"/> class.
        /// </summary>
        /// <param name="host">The host to connect to.</param>
        /// <param name="port">The port to connect to.</param>
        public TcpChannel(string host, int port)
        {
            _host = host;
            _port = port;
        }

        /// <summary>
        /// Connects to the TCP host.
        /// </summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            if (IsConnected) Disconnect();

            _client = new TcpClient();
            await _client.ConnectAsync(_host, _port, cancellationToken).ConfigureAwait(false);
            _stream = _client.GetStream();
        }

        /// <summary>
        /// Disconnects from the TCP host by disposing the channel.
        /// </summary>
        public void Disconnect()
        {
            Dispose();
        }

        /// <summary>
        /// Reads data from the TCP stream.
        /// </summary>
        public Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            if (_stream == null) throw new System.IO.IOException("Channel is not connected.");
            return _stream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Writes data to the TCP stream.
        /// </summary>
        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            if (_stream == null) throw new System.IO.IOException("Channel is not connected.");
            if (count == 0) return Task.CompletedTask;
            cancellationToken.ThrowIfCancellationRequested();
            return _stream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Disposes the underlying TCP client and network stream.
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
                _stream?.Dispose();
                _client?.Dispose();
            }

            _stream = null;
            _client = null;
            _disposed = true;
        }

        /// <summary>
        /// Finalizer for the TcpChannel.
        /// </summary>
        ~TcpChannel()
        {
            Dispose(false);
        }
    }
}