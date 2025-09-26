using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Services
{
    public class FileStreamVirtualReader(string filePath, int preferredPageSize = 4096) : IVirtualFileReader, IDisposable
    {
        private readonly FileStream _fs = filePath == null 
            ? throw new ArgumentNullException(nameof(filePath))
            : !File.Exists(filePath) 
                ? throw new FileNotFoundException("File not found.", filePath)
                : new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        private readonly long _length = _fs.Length;
        private readonly int _preferredPageSize = preferredPageSize;

        public long Length => _length;
        public int PageSize => _preferredPageSize;

        public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            long offset = pageIndex * pageSize;

            if (offset >= _length)
            {
                return new Page(pageIndex, ReadOnlyMemory<byte>.Empty, 0);
            }

            ct.ThrowIfCancellationRequested();

            long bytesToRead = Math.Min(pageSize, _length - offset);
            var buffer = new byte[bytesToRead];

            _fs.Seek(offset, SeekOrigin.Begin);

            int bytesRead = await _fs.ReadAsync(buffer, 0, (int)bytesToRead, ct).ConfigureAwait(false);

            var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);

            return new Page(pageIndex, memory, bytesRead);
        }

        public void Dispose()
        {
            _fs?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
