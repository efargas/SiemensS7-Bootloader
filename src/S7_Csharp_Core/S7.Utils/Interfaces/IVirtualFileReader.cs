using System;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Models;

namespace S7.Utils.Interfaces
{
    public interface IVirtualFileReader : IDisposable
    {
        Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct);
        long Length { get; }
        int PageSize { get; }
    }
}
