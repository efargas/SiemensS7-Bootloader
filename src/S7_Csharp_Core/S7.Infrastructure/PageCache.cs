using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Infrastructure
{
    public class PageCache : IVirtualFileReader, IDisposable
    {
        private readonly IVirtualFileReader _sourceReader;
        private readonly int _cacheSize;
        private readonly SemaphoreSlim _semaphore;

        private readonly Dictionary<long, LinkedListNode<Page>> _cache = new();
        private readonly LinkedList<Page> _lruList = new();
        private readonly Dictionary<long, Task<Page>> _ongoingFetches = new();
        private readonly object _lock = new();

        public PageCache(IVirtualFileReader sourceReader, int cacheSize = 128, int maxConcurrency = 4)
        {
            _sourceReader = sourceReader;
            _cacheSize = cacheSize;
            _semaphore = new SemaphoreSlim(maxConcurrency);
        }

        public long Length => _sourceReader.Length;
        public int PageSize => _sourceReader.PageSize;

        public Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            lock (_lock)
            {
                if (_cache.TryGetValue(pageIndex, out var node))
                {
                    _lruList.Remove(node);
                    _lruList.AddFirst(node);
                    return Task.FromResult(node.Value);
                }

                if (_ongoingFetches.TryGetValue(pageIndex, out var existingTask))
                {
                    return existingTask;
                }

                var fetchTask = FetchPageAsync(pageIndex, pageSize, ct);
                _ongoingFetches.Add(pageIndex, fetchTask);
                return fetchTask;
            }
        }

        private async Task<Page> FetchPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            await _semaphore.WaitAsync(ct);
            try
            {
                var page = await _sourceReader.ReadPageAsync(pageIndex, pageSize, ct);
                lock (_lock)
                {
                    if (_cache.Count >= _cacheSize)
                    {
                        var last = _lruList.Last;
                        if (last != null)
                        {
                            _cache.Remove(last.Value.PageIndex);
                            _lruList.RemoveLast();
                        }
                    }

                    var node = new LinkedListNode<Page>(page);
                    _lruList.AddFirst(node);
                    _cache.Add(pageIndex, node);
                }
                return page;
            }
            finally
            {
                lock (_lock)
                {
                    _ongoingFetches.Remove(pageIndex);
                }
                _semaphore.Release();
            }
        }

        public void Dispose()
        {
            _sourceReader?.Dispose();
            _semaphore?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
