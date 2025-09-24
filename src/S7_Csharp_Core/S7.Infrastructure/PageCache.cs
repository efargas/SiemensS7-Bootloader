using System;
using System.Collections.Concurrent;
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

        // Use Lazy<Task<Page>> so the factory runs once per key (dedupe)
        private readonly ConcurrentDictionary<long, Lazy<Task<Page>>> _inflight = new();

        // LRU structures protected by _lock
        private readonly Dictionary<long, LinkedListNode<Page>> _cache = new();
        private readonly LinkedList<Page> _lruList = new();
        private readonly object _lock = new();

        public PageCache(IVirtualFileReader sourceReader, int cacheSize = 128, int maxConcurrency = 4)
        {
            _sourceReader = sourceReader ?? throw new ArgumentNullException(nameof(sourceReader));
            if (cacheSize <= 0) throw new ArgumentOutOfRangeException(nameof(cacheSize));
            _cacheSize = cacheSize;
            _semaphore = new SemaphoreSlim(Math.Max(1, maxConcurrency));
        }

        public long Length => _sourceReader.Length;
        public int PageSize => _sourceReader.PageSize;

        public Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            // Fast path: return cached value if present.
            lock (_lock)
            {
                if (_cache.TryGetValue(pageIndex, out var node))
                {
                    // Move to front (most recently used)
                    _lruList.Remove(node);
                    _lruList.AddFirst(node);
                    return Task.FromResult(node.Value);
                }
            }

            // Use Lazy<Task<Page>> to dedupe concurrent factories.
            var lazy = _inflight.GetOrAdd(pageIndex, _ => new Lazy<Task<Page>>(() => FetchAndCachePageAsync(pageIndex, pageSize, ct), LazyThreadSafetyMode.ExecutionAndPublication));

            // Return the task produced by the Lazy wrapper.
            // Note: we intentionally do not remove the inflight entry on success here;
            // we only remove it on failure (see FetchAndCachePageAsync) to avoid races where another caller starts a duplicate fetch.
            return lazy.Value;
        }

        private async Task<Page> FetchAndCachePageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            // Wait on concurrency semaphore to limit concurrent source reads.
            await _semaphore.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // Double-check cache under lock before doing I/O (someone might have already cached it)
                lock (_lock)
                {
                    if (_cache.TryGetValue(pageIndex, out var existingNode))
                    {
                        _lruList.Remove(existingNode);
                        _lruList.AddFirst(existingNode);
                        return existingNode.Value;
                    }
                }

                // Read from source (can be canceled)
                var page = await _sourceReader.ReadPageAsync(pageIndex, pageSize, ct).ConfigureAwait(false);

                // Insert into cache under lock and perform deterministic eviction loop
                lock (_lock)
                {
                    // Another check in case page was cached while we were reading
                    if (_cache.TryGetValue(pageIndex, out var existingNode))
                    {
                        _lruList.Remove(existingNode);
                        _lruList.AddFirst(existingNode);
                        return existingNode.Value;
                    }

                    var newNode = new LinkedListNode<Page>(page);
                    _cache[pageIndex] = newNode;
                    _lruList.AddFirst(newNode);

                    // Evict until size constraint satisfied. Loop handles concurrent insert races.
                    while (_cache.Count > _cacheSize)
                    {
                        var lruNode = _lruList.Last;
                        if (lruNode == null) break;
                        _cache.Remove(lruNode.Value.PageIndex);
                        _lruList.RemoveLast();
                    }
                }

                return page;
            }
            catch (OperationCanceledException)
            {
                // If the read was canceled, remove inflight entry so subsequent requests can retry.
                _inflight.TryRemove(pageIndex, out _);
                throw;
            }
            catch (Exception)
            {
                // On failure, remove inflight so callers can retry and propagate the exception.
                _inflight.TryRemove(pageIndex, out _);
                throw;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public void Dispose()
        {
            // Attempt to dispose inner reader if it implements IDisposable
            if (_sourceReader is IDisposable d) d.Dispose();
            _semaphore?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
