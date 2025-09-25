using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils.Interfaces;

namespace S7_Csharp_Utility.Services
{
    public class VirtualizingHexList : IList<HexViewerService.HexRow>, IDisposable
    {
        private const int HexBytesPerLine = 16;
        public long FileSize => _reader.Length;
        private readonly IVirtualFileReader _reader;

        public VirtualizingHexList(IVirtualFileReader reader)
        {
            _reader = reader;
        }

        public HexViewerService.HexRow this[int index]
        {
            get => GetRowSync(index);
            set => throw new NotSupportedException();
        }

        /// <summary>
        /// Synchronous version of GetRowAsync for IList compatibility.
        /// Note: This may block the calling thread. Use GetRowAsync when possible.
        /// </summary>
        private HexViewerService.HexRow GetRowSync(int index)
        {
            // Use Task.Run to avoid potential deadlocks in UI contexts
            return Task.Run(async () => await GetRowAsync(index).ConfigureAwait(false)).GetAwaiter().GetResult();
        }

        private async Task<HexViewerService.HexRow> GetRowAsync(int index)
        {
            var offset = (long)index * HexBytesPerLine;
            if (offset >= FileSize)
            {
                throw new IndexOutOfRangeException();
            }

            // For simplicity, we read a whole page even for one row. The cache will handle it.
            var pageIndex = offset / _reader.PageSize;
            var offsetInPage = (int)(offset % _reader.PageSize);

            var page = await _reader.ReadPageAsync(pageIndex, _reader.PageSize, CancellationToken.None).ConfigureAwait(false);

            var rowLength = (int)Math.Min(HexBytesPerLine, page.Data.Length - offsetInPage);
            if (rowLength < 0) rowLength = 0;

            var buffer = page.Data.Slice(offsetInPage, rowLength).ToArray();

            var asciiString = new StringBuilder();
            var bytesArray = new string[HexBytesPerLine];
            var offsetsArray = new long[HexBytesPerLine];

            for (int j = 0; j < HexBytesPerLine; j++)
            {
                if (j < rowLength)
                {
                    var b = buffer[j];
                    bytesArray[j] = b.ToString("X2");
                    offsetsArray[j] = offset + j;
                    asciiString.Append(char.IsControl((char)b) ? '.' : (char)b);
                }
                else
                {
                    bytesArray[j] = string.Empty;
                    offsetsArray[j] = -1L;
                    asciiString.Append(' ');
                }
            }

            return new HexViewerService.HexRow
            {
                Address = $"{offset:X8}",
                Ascii = asciiString.ToString(),
                ByteOffset = offset,
                RawBytes = buffer,
                Bytes = bytesArray,
                Offsets = offsetsArray
            };
        }

        public int Count => (int)((FileSize + HexBytesPerLine - 1) / HexBytesPerLine);

        public bool IsReadOnly => true;

        public void Add(HexViewerService.HexRow item) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
        public bool Contains(HexViewerService.HexRow item) => throw new NotSupportedException();
        public void CopyTo(HexViewerService.HexRow[] array, int arrayIndex) => throw new NotSupportedException();
        public int IndexOf(HexViewerService.HexRow item) => throw new NotSupportedException();
        public void Insert(int index, HexViewerService.HexRow item) => throw new NotSupportedException();
        public bool Remove(HexViewerService.HexRow item) => throw new NotSupportedException();
        public void RemoveAt(int index) => throw new NotSupportedException();

        public IEnumerator<HexViewerService.HexRow> GetEnumerator()
        {
            for (int i = 0; i < Count; i++)
            {
                yield return this[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        /// <summary>
        /// Reads a range of bytes from the file.
        /// Note: This may block the calling thread. Use ReadRangeAsync when possible.
        /// </summary>
        public byte[] ReadRange(long offset, int length)
        {
            // Use Task.Run to avoid potential deadlocks in UI contexts
            return Task.Run(async () => await ReadRangeAsync(offset, length).ConfigureAwait(false)).GetAwaiter().GetResult();
        }

        private async Task<byte[]> ReadRangeAsync(long offset, int length)
        {
            var buffer = new byte[length];
            int read_total = 0;
            while (read_total < length)
            {
                var pageIndex = offset / _reader.PageSize;
                var offsetInPage = (int)(offset % _reader.PageSize);
                var page = await _reader.ReadPageAsync(pageIndex, _reader.PageSize, CancellationToken.None).ConfigureAwait(false);

                var bytesToCopy = Math.Min(page.Data.Length - offsetInPage, length - read_total);
                if (bytesToCopy <= 0) break;

                var destination = new Memory<byte>(buffer, read_total, bytesToCopy);
                page.Data.Slice(offsetInPage, bytesToCopy).CopyTo(destination);

                read_total += bytesToCopy;
                offset += bytesToCopy;
            }
            return buffer;
        }

        public IEnumerable<long> Search(byte[] pattern, long startOffset, CancellationToken cancellationToken)
        {
            // This is complex to reimplement on top of a virtual reader.
            // For now, I will leave it as not implemented.
            // A proper implementation would need to read pages and search within them, handling patterns that span across page boundaries.
            throw new NotImplementedException("Search is not supported with the new virtual reader yet.");
        }

        public void Dispose()
        {
            _reader.Dispose();
        }
    }
}
