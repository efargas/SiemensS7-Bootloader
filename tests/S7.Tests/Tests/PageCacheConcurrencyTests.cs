using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using S7.Infrastructure;
using S7.Utils.Interfaces;
using S7.Utils.Models;
using Xunit;

namespace S7.Tests.Tests
{
    public class PageCacheConcurrencyTests
    {
        [Fact(Timeout = 30_000)]
        public async Task PageCache_ConcurrentAccess_DoesNotThrow()
        {
            // Arrange
            var mockReader = new Mock<IVirtualFileReader>();
            mockReader.Setup(r => r.ReadPageAsync(It.IsAny<long>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns((long pageIndex, int pageSize, CancellationToken ct) =>
                    Task.FromResult(new Page(pageIndex, new byte[pageSize])));

            int capacity = 4;
            var cache = new PageCache(mockReader.Object, capacity);

            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            var rnd = new Random(123456);

            // Act
            var tasks = Enumerable.Range(0, 100).Select(_ => Task.Run(async () =>
            {
                int page = rnd.Next(0, 10);
                await cache.ReadPageAsync(page, 1024, cts.Token).ConfigureAwait(false);
            }, cts.Token)).ToArray();

            Func<Task> action = async () => await Task.WhenAll(tasks);

            // Assert
            await action.Should().NotThrowAsync();
        }
    }
}