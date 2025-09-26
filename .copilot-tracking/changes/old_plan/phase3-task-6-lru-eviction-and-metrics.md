### LRU Eviction and Metrics for PageCache

- **Added Cache Hit/Miss Counters:** Implemented `CacheHits` and `CacheMisses` properties in the `PageCache` class to track cache performance. These counters are incremented appropriately during page read operations.
- **Enabled LRU Eviction Test:** The previously skipped test `ReadPageAsync_WhenCacheIsFull_EvictsLeastRecentlyUsed` in `PageCacheTests.cs` has been enabled.
- **Added Cache Counter Verification Test:** A new test `ReadPageAsync_CacheHitAndMiss_UpdatesCounters` has been added to `PageCacheTests.cs` to verify the correct functioning of the cache hit and miss counters.
