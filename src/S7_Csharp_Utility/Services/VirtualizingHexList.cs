using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;

namespace S7_Csharp_Utility.Services
{
    public class VirtualizingHexList : IList<HexViewerService.HexRow>, IDisposable
    {
        private const int HexBytesPerLine = 16;
        public long FileSize { get; }
        private readonly MemoryMappedFile _mmf;
        private readonly MemoryMappedViewAccessor _accessor;

        public VirtualizingHexList(string filePath)
        {
            var fileInfo = new FileInfo(filePath);
            FileSize = fileInfo.Length;
            _mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            _accessor = _mmf.CreateViewAccessor(0, FileSize, MemoryMappedFileAccess.Read);
        }

        public HexViewerService.HexRow this[int index]
        {
            get
            {
                var offset = (long)index * HexBytesPerLine;
                if (offset >= FileSize)
                {
                    throw new IndexOutOfRangeException();
                }

                var rowLength = (int)Math.Min(HexBytesPerLine, FileSize - offset);
                var buffer = new byte[rowLength];
                _accessor.ReadArray(offset, buffer, 0, rowLength);

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
            set => throw new NotSupportedException();
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

        public byte[] ReadRange(long offset, int length)
        {
            var buffer = new byte[length];
            _accessor.ReadArray(offset, buffer, 0, length);
            return buffer;
        }

        public IEnumerable<long> Search(byte[] pattern, long startOffset, CancellationToken cancellationToken)
        {
            if (pattern == null || pattern.Length == 0 || FileSize < pattern.Length)
                yield break;

            long endOffset = FileSize - pattern.Length + 1;
            int patternLength = pattern.Length;
            const int bufferSize = 4 * 1024 * 1024; // 4MB
            byte[] buffer = new byte[bufferSize];

            long currentOffset = startOffset;

            while (currentOffset < endOffset)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int bytesToRead = (int)Math.Min(bufferSize, FileSize - currentOffset);
                _accessor.ReadArray(currentOffset, buffer, 0, bytesToRead);

                int searchLimit = bytesToRead - patternLength + 1;
                for (int i = 0; i < searchLimit; i++)
                {
                    bool match = true;
                    for (int j = 0; j < patternLength; j++)
                    {
                        if (buffer[i + j] != pattern[j])
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        yield return currentOffset + i;
                    }
                }

                long nextOffset = currentOffset + bytesToRead - (patternLength - 1);
                if (nextOffset <= currentOffset)
                {
                    currentOffset++;
                }
                else
                {
                    currentOffset = nextOffset;
                }
            }
        }

        public void Dispose()
        {
            _accessor.Dispose();
            _mmf.Dispose();
        }
    }
}
