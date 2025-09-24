using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using S7.Net;
using S7.Net.Interfaces;

namespace S7_Csharp_Utility.Tests
{
    public class PlcClientTests
    {
        [Fact]
        public async Task PerformHandshakeAsync_CancellationRequested_ThrowsOperationCanceledException()
        {
            // Arrange
            var mockChannel = new Mock<ICommunicationChannel>();
            var cts = new CancellationTokenSource();

            mockChannel.Setup(c => c.WriteAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns<byte[], int, int, CancellationToken>(async (buffer, offset, count, cancellationToken) =>
                {
                    await Task.Delay(100, cancellationToken);
                });

            mockChannel.Setup(c => c.ReadAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns<byte[], int, int, CancellationToken>(async (buffer, offset, count, cancellationToken) =>
                {
                    await Task.Delay(100, cancellationToken);
                    return 0;
                });

            var plcClient = new PlcClient(mockChannel.Object, _ => { });

            // Act
            var task = plcClient.PerformHandshakeAsync(cts.Token);
            cts.Cancel();

            // Assert
            await Assert.ThrowsAsync<TaskCanceledException>(() => task);
        }
    }
}
