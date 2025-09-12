using S7.Net.Interfaces;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace S7.Net.Channels
{
    public class TcpChannel : ICommunicationChannel
    {
        private readonly string _host;
        private readonly int _port;
        private TcpClient? _client;
        private NetworkStream? _stream;

        public bool IsConnected => _client?.Connected ?? false;
        public bool DataAvailable => _stream?.DataAvailable ?? false;

        public TcpChannel(string host, int port)
        {
            _host = host;
            _port = port;
        }

        public async Task ConnectAsync()
        {
            if (IsConnected) Disconnect();
            _client = new TcpClient();
            await _client.ConnectAsync(_host, _port);
            _stream = _client.GetStream();
        }

        public void Disconnect()
        {
            _stream?.Close();
            _client?.Close();
            _stream = null;
            _client = null;
        }

        public async Task<int> ReadAsync(byte[] buffer, int offset, int count)
        {
            if (_stream == null) throw new System.IO.IOException("Not connected.");
            return await _stream.ReadAsync(buffer, offset, count);
        }

        public async Task WriteAsync(byte[] buffer, int offset, int count)
        {
            if (_stream == null) throw new System.IO.IOException("Not connected.");
            await _stream.WriteAsync(buffer, offset, count);
        }
    }
}
