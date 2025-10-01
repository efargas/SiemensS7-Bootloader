using System;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Core.Tests.TestHelpers
{
    // Mock reader that counts calls and can delay/cancel
    public class DelayedMockReader : IVirtualFileReader
    {
        public long Length { get; }
        public int PageSize { get; }
        private readonly TimeSpan _delay;
        private readonly Func<long, byte> _pattern;
        public int CallCount;

        public DelayedMockReader(long length, int pageSize, TimeSpan delay, Func<long, byte>? pattern = null)
        {
            Length = length;
            PageSize = pageSize;
            _delay = delay;
            _pattern = pattern ?? (idx => (byte)(idx % 256));
            CallCount = 0;
        }

        public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            Interlocked.Increment(ref CallCount);
            if (_delay > TimeSpan.Zero)
            {
                await Task.Delay(_delay, ct).ConfigureAwait(false);
            }

            var actualSize = Math.Min(pageSize, (int)Math.Max(0, Length - pageIndex * pageSize));
            var buffer = new byte[actualSize];
            for (int i = 0; i < actualSize; i++)
            {
                buffer[i] = _pattern(pageIndex);
            }

            return new Page(pageIndex, buffer, actualSize);
        }

        public void Dispose() { }
    }

    // Mock reader that throws on read for testing failure token handling
    public class FailingMockReader : IVirtualFileReader
    {
        public long Length { get; }
        public int PageSize { get; }
        private readonly TimeSpan _delay;

        public FailingMockReader(long length, int pageSize, TimeSpan delay)
        {
            Length = length;
            PageSize = pageSize;
            _delay = delay;
        }

        public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            if (_delay > TimeSpan.Zero) await Task.Delay(_delay, ct).ConfigureAwait(false);
            throw new InvalidOperationException("Simulated read failure");
        }

        public void Dispose() { }
    }
}
