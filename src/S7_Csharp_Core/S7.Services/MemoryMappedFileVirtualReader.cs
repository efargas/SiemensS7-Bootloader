using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;
using S7.Utils.Models;

namespace S7.Services
{
    public class MemoryMappedFileVirtualReader(string filePath, int preferredPageSize = 4096) : IVirtualFileReader, IDisposable
    {
        private readonly FileInfo _fileInfo = InitializeFileInfo(filePath);
        private readonly int _preferredPageSize = preferredPageSize;
        private readonly MemoryMappedFile _mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);

        private static FileInfo InitializeFileInfo(string filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found.", filePath);
                
            return new FileInfo(filePath);
        }

        public long Length => _fileInfo.Length;
        public int PageSize => _preferredPageSize;

        public Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
        {
            long offset = pageIndex * pageSize;
            long length = _fileInfo.Length;

            if (offset >= length)
            {
                return Task.FromResult(new Page(pageIndex, ReadOnlyMemory<byte>.Empty, 0));
            }

            ct.ThrowIfCancellationRequested();

            long bytesToRead = Math.Min(pageSize, length - offset);

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
