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
        private readonly FileStream _fs = InitializeFileStream(filePath);
        private readonly int _preferredPageSize = preferredPageSize;

        private static FileStream InitializeFileStream(string filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found.", filePath);
                
            return new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public long Length => _fs.Length;
        public int PageSize => _preferredPageSize;

        public async Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            long offset = pageIndex * pageSize;
            long length = _fs.Length;

            if (offset >= length)
            {
                return new Page(pageIndex, ReadOnlyMemory<byte>.Empty, 0);
            }

            ct.ThrowIfCancellationRequested();

            long bytesToRead = Math.Min(pageSize, length - offset);
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
