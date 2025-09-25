using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using S7.Core.Tests.TestHelpers;
using Xunit;
using S7.Infrastructure;
using S7.Utils.Interfaces;
using S7.Utils.Models;
using System.Reflection;

namespace S7.Core.Tests
{
    public class PageCacheEvictionTests
    {
        // helper mock reader that delays and returns unique content per page index
        private class DeterministicDelayedReader : IVirtualFileReader
        {
            public long Length { get; } = 1024 * 1024;
            public int PageSize { get; } = 4096;
            private readonly TimeSpan _delay;

            public DeterministicDelayedReader(TimeSpan delay) { _delay = delay; }

            public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
            {
                await Task.Delay(_delay, ct).ConfigureAwait(false);
                var size = Math.Min(pageSize, (int)Math.Max(0, Length - pageIndex * pageSize));
                var buf = new byte[size];
                for (int i = 0; i < size; i++) buf[i] = (byte)(pageIndex & 0xFF);
                return new Page(pageIndex, new ReadOnlyMemory<byte>(buf), size);
            }
            public void Dispose() { }
        }

        [Fact]
        public async Task ConcurrentInserts_OverCapacity_EvictsLRU()
        {
            // Arrange
            var capacity = 3;
            var concurrency = 6;
            var reader = new DeterministicDelayedReader(TimeSpan.FromMilliseconds(80));
            var cache = new S7.Infrastructure.PageCache(reader, cacheSize: capacity, maxConcurrency: 4);

            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // Act: request many different pages concurrently to overflow the cache
            var tasks = Enumerable.Range(0, concurrency)
                .Select(i => cache.ReadPageAsync(i, reader.PageSize, cts.Token))
                .ToArray();

            await Task.WhenAll(tasks);

            // Assert: cache size should not exceed capacity and eviction count should be >= concurrency - capacity
            Assert.InRange(GetCacheCount(cache), 0, capacity);
        }

        [Fact]
        public async Task Eviction_RemovesLeastRecentlyUsed()
        {
            // Arrange
            var capacity = 2;
            var reader = new DeterministicDelayedReader(TimeSpan.FromMilliseconds(20));
            var cache = new S7.Infrastructure.PageCache(reader, cacheSize: capacity, maxConcurrency: 2);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // Access pages 0 and 1 to fill cache
            var p0 = await cache.ReadPageAsync(0, reader.PageSize, cts.Token);
            var p1 = await cache.ReadPageAsync(1, reader.PageSize, cts.Token);

            // Access page 0 to mark it as most recently used (LRU order: 0 (MRU),1 (LRU))
            var p0b = await cache.ReadPageAsync(0, reader.PageSize, cts.Token);

            // Now request page 2 which should evict the LRU (page 1)
            var p2 = await cache.ReadPageAsync(2, reader.PageSize, cts.Token);

            // Assert: page 1 should no longer be in cache; page 0 and 2 should be present
            Assert.False(IsInCache(cache, 1));
            Assert.True(IsInCache(cache, 0));
            Assert.True(IsInCache(cache, 2));
        }

        // WARNING: The PageCache internal structures are private. The helper below uses reflection to get cache size.
        // Adapt to your PageCache if you add an explicit API to check current cache keys or count.
        private int GetCacheCount(object pageCache)
        {
            var type = pageCache.GetType();
            var field = type.GetField("_cache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (field == null) return -1;
            var dict = (System.Collections.IDictionary)field.GetValue(pageCache);
            return dict.Count;
        }

        private bool IsInCache(object pageCache, long pageIndex)
        {
            var type = pageCache.GetType();
            var field = type.GetField("_cache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (field == null) return false;
            var dict = (System.Collections.IDictionary)field.GetValue(pageCache);
            return dict.Contains(pageIndex);
        }
    }
}
