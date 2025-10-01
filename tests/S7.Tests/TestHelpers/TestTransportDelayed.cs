using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Tests.TestHelpers
{
    // Simulates a slow transport that returns data in chunks and supports cancellation.
    public class TestTransportDelayed : ITestTransport
    {
        private readonly byte[] _readData;
        private int _readPos;
        private readonly int _chunkSize;
        private readonly int _delayMs;
        private readonly Exception? _throwAfterReads;

        public TestTransportDelayed(byte[] readData, int chunkSize = 128, int delayMs = 50, Exception? throwAfterReads = null)
        {
            _readData = readData ?? Array.Empty<byte>();
            _chunkSize = Math.Max(1, chunkSize);
            _delayMs = delayMs;
            _throwAfterReads = throwAfterReads;
        }

        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            if (_throwAfterReads != null && _readPos >= _readData.Length / 2)
            {
                throw _throwAfterReads;
            }

            await Task.Delay(_delayMs, ct).ConfigureAwait(false);

            if (_readPos >= _readData.Length) return 0;

            int toCopy = Math.Min(_chunkSize, Math.Min(count, _readData.Length - _readPos));
            Array.Copy(_readData, _readPos, buffer, offset, toCopy);
            _readPos += toCopy;
            return toCopy;
        }

        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => new ValueTask(Task.CompletedTask);
    }
}