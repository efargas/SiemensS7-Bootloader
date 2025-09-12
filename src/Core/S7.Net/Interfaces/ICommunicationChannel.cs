using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    public interface ICommunicationChannel
    {
        bool IsConnected { get; }
        bool DataAvailable { get; }

        Task ConnectAsync();
        void Disconnect();
        Task<int> ReadAsync(byte[] buffer, int offset, int count);
        Task WriteAsync(byte[] buffer, int offset, int count);
    }
}
