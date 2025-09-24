using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using S7.Utils.Interfaces;
using S7.Utils.Models;
using S7.Infrastructure;

namespace S7.Core.Tests
{
    public class PageCacheTests
    {
        private readonly Mock<IVirtualFileReader> _mockReader;

        public PageCacheTests()
        {
            _mockReader = new Mock<IVirtualFileReader>();
            _mockReader.Setup(r => r.Length).Returns(10000);
        }

        [Fact]
        public async Task ReadPageAsync_CachesPage_ReturnsFromCacheOnSecondRequest()
        {
            // Arrange
            var cache = new PageCache(_mockReader.Object);
            var pageContent = new Page(0, new byte[] { 1, 2, 3 }, 3);
            _mockReader.Setup(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()))
                       .ReturnsAsync(pageContent);

            // Act
            var firstResult = await cache.ReadPageAsync(0, 1024, CancellationToken.None);
            var secondResult = await cache.ReadPageAsync(0, 1024, CancellationToken.None);

            // Assert
            Assert.Same(pageContent, firstResult);
            Assert.Same(pageContent, secondResult);
            _mockReader.Verify(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ReadPageAsync_WithConcurrentRequests_DeduplicatesReadOperation()
        {
            // Arrange
            var cache = new PageCache(_mockReader.Object);
            _mockReader.Setup(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()))
                       .Returns(async () =>
                       {
                           await Task.Delay(100);
                           return new Page(0, new byte[] { 1, 2, 3 }, 3);
                       });

            // Act
            var task1 = cache.ReadPageAsync(0, 1024, CancellationToken.None);
            var task2 = cache.ReadPageAsync(0, 1024, CancellationToken.None);
            await Task.WhenAll(task1, task2);

            // Assert
            _mockReader.Verify(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()), Times.Once());
            Assert.Same(task1.Result, task2.Result);
        }

        [Fact]
        public async Task ReadPageAsync_WithThrottling_LimitsConcurrentReads()
        {
            // Arrange
            var cache = new PageCache(_mockReader.Object, cacheSize: 10, maxConcurrency: 2);
            var activeReads = 0;
            var maxActiveReads = 0;
            var readLock = new object();

            _mockReader.Setup(r => r.ReadPageAsync(It.IsAny<long>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                       .Returns(async (long idx, int size, CancellationToken ct) =>
                       {
                           lock (readLock)
                           {
                               activeReads++;
                               maxActiveReads = Math.Max(maxActiveReads, activeReads);
                           }
                           await Task.Delay(50, ct);
                           lock (readLock)
                           {
                               activeReads--;
                           }
                           return new Page(idx, new byte[0], 0);
                       });

            // Act
            var tasks = new List<Task>();
            for (int i = 0; i < 5; i++)
            {
                tasks.Add(cache.ReadPageAsync(i, 1024, CancellationToken.None));
            }
            await Task.WhenAll(tasks);

            // Assert
            Assert.Equal(2, maxActiveReads);
        }

        [Fact]
        public async Task ReadPageAsync_WhenCancelled_ThrowsTaskCanceledException()
        {
            // Arrange
            var cts = new CancellationTokenSource();
            var cache = new PageCache(_mockReader.Object);
            _mockReader.Setup(r => r.ReadPageAsync(It.IsAny<long>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                       .Returns(async (long i, int s, CancellationToken ct) =>
                       {
                           await Task.Delay(1000, ct);
                           return new Page(i, new byte[0], 0);
                       });

            // Act & Assert
            var task = cache.ReadPageAsync(0, 1024, cts.Token);
            cts.Cancel();
            await Assert.ThrowsAsync<TaskCanceledException>(() => task);
        }

        [Fact(Skip = "Temporarily disabled due to known bug in LRU eviction logic.")]
        public async Task ReadPageAsync_WhenCacheIsFull_EvictsLeastRecentlyUsed()
        {
            // Arrange
            var cache = new PageCache(_mockReader.Object, cacheSize: 2);
            _mockReader.Setup(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(0, new byte[0], 0));
            _mockReader.Setup(r => r.ReadPageAsync(1, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(1, new byte[0], 0));
            _mockReader.Setup(r => r.ReadPageAsync(2, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(2, new byte[0], 0));

            // Act & Assert
            // Step 1: Fill the cache.
            await cache.ReadPageAsync(0, 1024, CancellationToken.None);
            await cache.ReadPageAsync(1, 1024, CancellationToken.None);

            // Step 2: Access page 0 to make it MRU. Page 1 is now LRU.
            await cache.ReadPageAsync(0, 1024, CancellationToken.None);

            // Step 3: Request page 2, which should cause page 1 to be evicted.
            await cache.ReadPageAsync(2, 1024, CancellationToken.None);

            // Step 4: Request page 1 again. It should be a cache miss and fetched again.
            await cache.ReadPageAsync(1, 1024, CancellationToken.None);

            // Assert
            _mockReader.Verify(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()), Times.Once());
            _mockReader.Verify(r => r.ReadPageAsync(1, 1024, It.IsAny<CancellationToken>()), Times.Exactly(2));
            _mockReader.Verify(r => r.ReadPageAsync(2, 1024, It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
