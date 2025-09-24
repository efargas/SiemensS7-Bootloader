using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Services
{
    public class MemoryMappedFileVirtualReader : IVirtualFileReader, IDisposable
    {
        private readonly MemoryMappedFile _mmf;
        private readonly long _length;
        private readonly int _preferredPageSize;

        public MemoryMappedFileVirtualReader(string filePath, int preferredPageSize = 4096)
        {
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found.", filePath);

            var fileInfo = new FileInfo(filePath);
            _length = fileInfo.Length;
            _preferredPageSize = preferredPageSize;

            _mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        }

        public long Length => _length;
        public int PageSize => _preferredPageSize;

        public Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            long offset = pageIndex * pageSize;

            if (offset >= _length)
            {
                return Task.FromResult(new Page(pageIndex, ReadOnlyMemory<byte>.Empty, 0));
            }

            ct.ThrowIfCancellationRequested();

            long bytesToRead = Math.Min(pageSize, _length - offset);

            using (var accessor = _mmf.CreateViewAccessor(offset, bytesToRead, MemoryMappedFileAccess.Read))
            {
                var buffer = new byte[bytesToRead];
                accessor.ReadArray(0, buffer, 0, buffer.Length);
                var memory = new ReadOnlyMemory<byte>(buffer);
                return Task.FromResult(new Page(pageIndex, memory, (int)bytesToRead));
            }
        }

        public void Dispose()
        {
            _mmf?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
