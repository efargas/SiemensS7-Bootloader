using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;
using S7.Core.Commands;
using S7.Net.Interfaces;
using Moq;
using S7.Net;
using Microsoft.Extensions.Logging;

namespace S7.Tests.Tests
{
    public class DumpCancellationTests
    {
        private class TestableMemoryDumpCommandHandler : MemoryDumpCommandHandler
        {
            public TestableMemoryDumpCommandHandler(ILogger<MemoryDumpCommandHandler> logger, PayloadManager payloadManager, ICommunicationChannel testChannel)
                : base(logger, payloadManager, testChannel)
            {
            }

            public Task<CommandResult> TestExecuteAsync(MemoryDumpOptions options, CancellationToken cancellationToken)
            {
                return base.ExecuteAsync(options, cancellationToken);
            }
        }

        [Fact(Timeout = 20_000)]
        public async Task DumpAsync_Cancelled_ClosesStreamsAndLeavesPartialFile()
        {
            // Arrange
            var mockChannel = new Mock<ICommunicationChannel>();
            mockChannel.Setup(c => c.ReadAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(async (byte[] buffer, int offset, int count, CancellationToken ct) =>
                {
                    await Task.Delay(5000, ct);
                    return 0;
                });

            var tmpFile = Path.Combine(Path.GetTempPath(), $"mem_dump_test_{Guid.NewGuid():N}.bin");
            var partial = tmpFile + ".partial";
            var cts = new CancellationTokenSource();

            var logger = new Mock<ILogger<MemoryDumpCommandHandler>>().Object;
            var payloadManager = new Mock<PayloadManager>("");
            payloadManager.Setup(p => p.GetMemoryDumperPayloadAsync(It.IsAny<string>())).ReturnsAsync(new byte[10]);

            var dumper = new TestableMemoryDumpCommandHandler(logger, payloadManager.Object, mockChannel.Object);

            var options = new MemoryDumpOptions
            {
                Address = 0x1000,
                Length = 20000,
                OutputPath = Path.GetDirectoryName(tmpFile),
                CustomFilename = Path.GetFileName(tmpFile),
                ChannelConfig = new() { Mode = "TCP", Host = "localhost", Port = 102 },
                PayloadPath = ""
            };

            // Act
            var dumpTask = dumper.TestExecuteAsync(options, cts.Token);

            await Task.Delay(300);
            cts.Cancel();

            // Assert
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await dumpTask);

            File.Exists(partial).Should().BeTrue();
            try { File.Delete(partial); } catch { /* best-effort cleanup */ }
        }
    }
}