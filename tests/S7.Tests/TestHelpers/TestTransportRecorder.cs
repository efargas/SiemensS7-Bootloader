using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Tests.TestHelpers
{
    // Pre-sequenced reads and write recording for assertions.
    public class TestTransportRecorder : ITestTransport
    {
        private readonly byte[] _readData;
        private int _readPos;
        public ConcurrentQueue<byte[]> Writes { get; } = new();

        public TestTransportRecorder(byte[] readData)
        {
            _readData = readData ?? Array.Empty<byte>();
        }

        public Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            if (_readPos >= _readData.Length) return Task.FromResult(0);

            int toCopy = Math.Min(count, _readData.Length - _readPos);
            Array.Copy(_readData, _readPos, buffer, offset, toCopy);
            _readPos += toCopy;
            return Task.FromResult(toCopy);
        }

        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var copy = new byte[count];
            Array.Copy(buffer, offset, copy, 0, count);
            Writes.Enqueue(copy);
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => new ValueTask(Task.CompletedTask);
    }
}