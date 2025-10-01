using System.Threading;
using System.Threading.Tasks;

namespace S7.Net.Interfaces
{
    /// <summary>
    /// Defines a communication channel for the PLC.
    /// </summary>
    public interface ICommunicationChannel
    {
        /// <summary>
        /// Indicates whether the channel is connected.
        /// </summary>
        bool IsConnected { get; }
        /// <summary>
        /// Indicates whether there is data available to be read.
        /// </summary>
        bool DataAvailable { get; }

        /// <summary>
        /// Connects to the PLC.
        /// </summary>
        Task ConnectAsync(CancellationToken cancellationToken = default);
        /// <summary>
        /// Disconnects from the PLC.
        /// </summary>
        void Disconnect();
        /// <summary>
        /// Reads data from the PLC.
        /// </summary>
        /// <param name="buffer">The buffer to read data into.</param>
        /// <param name="offset">The offset in the buffer to start writing to.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of bytes read.</returns>
        Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default);
        /// <summary>
        /// Writes data to the PLC.
        /// </summary>
        /// <param name="buffer">The buffer containing the data to write.</param>
        /// <param name="offset">The offset in the buffer to start writing from.</param>
        /// <param name="count">The number of bytes to write.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default);
    }
}
