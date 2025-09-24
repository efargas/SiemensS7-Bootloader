using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Tests.TestHelpers
{
    public interface ITestTransport : IAsyncDisposable
    {
        Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct);
        Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct);
    }
}