using S7.Net.Interfaces;
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
        public bool IsConnected => _client?.Connected ?? false;
        /// <summary>
        /// Indicates whether there is data available to be read.
        /// </summary>
        public bool DataAvailable => _stream?.DataAvailable ?? false;

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
            if (IsConnected) Disconnect();
            _client = new TcpClient();
            await _client.ConnectAsync(_host, _port, cancellationToken);
            _stream = _client.GetStream();
        }

        /// <summary>
        /// Disconnects from the TCP host.
        /// </summary>
        public void Disconnect()
        {
        if (_stream != null)
        {
            _stream.Close();
            _stream.Dispose();
            _stream = null;
        }
        if (_client != null)
        {
            _client.Close();
            _client.Dispose();
            _client = null;
        }
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
            Disconnect();
        }

        _disposed = true;
        }

        /// <summary>
        /// Reads data from the TCP stream.
        /// </summary>
        /// <param name="buffer">The buffer to read data into.</param>
        /// <param name="offset">The offset in the buffer to start writing to.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of bytes read.</returns>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_stream == null) throw new System.IO.IOException("Not connected.");
            return await _stream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        /// <summary>
        /// Writes data to the TCP stream.
        /// </summary>
        /// <param name="buffer">The buffer containing the data to write.</param>
        /// <param name="offset">The offset in the buffer to start writing from.</param>
        /// <param name="count">The number of bytes to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_stream == null) throw new System.IO.IOException("Not connected.");
            await _stream.WriteAsync(buffer, offset, count, cancellationToken);
        }
    }
}
