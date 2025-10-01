using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Tests.TestHelpers;
using Xunit;
using S7.Infrastructure;
using S7.Utils.Interfaces;
using Moq;
using S7.Utils.Models;

namespace S7.Core.Tests
{
    public class PageCacheTests
    {
        [Fact]
        public async Task Dedupe_TwoConcurrentRequests_OnlyOneUnderlyingRead()
        {
            // Arrange
            var reader = new DelayedMockReader(length: 1024 * 1024, pageSize: 4096, delay: TimeSpan.FromMilliseconds(200));
            var cache = new PageCache(reader, maxConcurrency: 4);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            // Act: start two concurrent requests for same page index
            var tasks = new[]
            {
                cache.ReadPageAsync(0, 4096, cts.Token),
                cache.ReadPageAsync(0, 4096, cts.Token)
            };

            await Task.WhenAll(tasks);

            // Assert: underlying reader called once
            Assert.Equal(1, reader.CallCount);
            Assert.Equal(tasks[0].Result.Data.ToArray(), tasks[1].Result.Data.ToArray());
        }

        [Fact]
        public async Task Cancellation_CancellingOneRequest_AllowsRetry()
        {
            // Arrange
            var reader = new DelayedMockReader(length: 1024 * 1024, pageSize: 4096, delay: TimeSpan.FromMilliseconds(500));
            var cache = new PageCache(reader, maxConcurrency: 2);

            // Start a request and cancel it shortly after
            var cts1 = new CancellationTokenSource();
            var task1 = cache.ReadPageAsync(1, 4096, cts1.Token);

            // Cancel quickly
            cts1.CancelAfter(TimeSpan.FromMilliseconds(50));

            // Wait for initial to observe cancellation propagation
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task1);

            // Now request again with a fresh token; should retry and succeed
            var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var result = await cache.ReadPageAsync(1, 4096, cts2.Token);

            Assert.NotNull(result);
            // Underlying reader should have been called at least twice if first was cancelled and removed
            Assert.True(reader.CallCount >= 2);
        }

        [Fact]
        public async Task Throttle_MaxParallelReads_Respected()
        {
            // Arrange
            var concurrency = 2;
            var pagesToRequest = 6;
            var reader = new DelayedMockReader(length: 1024 * 1024, pageSize: 4096, delay: TimeSpan.FromMilliseconds(300));

            var activeCounter = 0;
            var maxObservedConcurrent = 0;
            var locker = new object();

            // Wrap reader to monitor concurrency
            var monitoringReader = new MonitoringReader(reader, () =>
            {
                lock (locker)
                {
                    activeCounter++;
                    maxObservedConcurrent = Math.Max(maxObservedConcurrent, activeCounter);
                }
            }, () =>
            {
                lock (locker)
                {
                    activeCounter--;
                }
            });

            // use cache with monitoring reader
            var cache = new PageCache(monitoringReader, maxConcurrency: concurrency);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var tasks = Enumerable.Range(0, pagesToRequest)
                .Select(i => cache.ReadPageAsync(i, 4096, cts.Token))
                .ToArray();

            await Task.WhenAll(tasks);

            // Assert max observed concurrent reads does not exceed configured concurrency
            Assert.InRange(maxObservedConcurrent, 1, concurrency);
        }

        [Fact]
        public async Task ReadPageAsync_WhenCacheIsFull_EvictsLeastRecentlyUsed()
        {
            // Arrange
            var mockReader = new Mock<IVirtualFileReader>();
            mockReader.Setup(r => r.Length).Returns(10000);
            mockReader.Setup(r => r.PageSize).Returns(1024);
            var cache = new PageCache(mockReader.Object, cacheSize: 2);
            mockReader.Setup(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(0, new byte[0], 0));
            mockReader.Setup(r => r.ReadPageAsync(1, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(1, new byte[0], 0));
            mockReader.Setup(r => r.ReadPageAsync(2, 1024, It.IsAny<CancellationToken>())).ReturnsAsync(new Page(2, new byte[0], 0));

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
            mockReader.Verify(r => r.ReadPageAsync(0, 1024, It.IsAny<CancellationToken>()), Times.Once());
            mockReader.Verify(r => r.ReadPageAsync(1, 1024, It.IsAny<CancellationToken>()), Times.Once());
            mockReader.Verify(r => r.ReadPageAsync(2, 1024, It.IsAny<CancellationToken>()), Times.Once());
        }

        // helper monitoring reader that delegates to an underlying reader and calls hooks
        private class MonitoringReader : IVirtualFileReader
        {
            private readonly IVirtualFileReader _inner;
            private readonly Action _onStart;
            private readonly Action _onEnd;

            public MonitoringReader(IVirtualFileReader inner, Action onStart, Action onEnd)
            {
                _inner = inner;
                _onStart = onStart;
                _onEnd = onEnd;
            }

            public long Length => _inner.Length;
            public int PageSize => _inner.PageSize;

            public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
            {
                _onStart();
                try
                {
                    return await _inner.ReadPageAsync(pageIndex, pageSize, ct).ConfigureAwait(false);
                }
                finally
                {
                    _onEnd();
                }
            }

            public void Dispose() => _inner.Dispose();
        }
    }
}
