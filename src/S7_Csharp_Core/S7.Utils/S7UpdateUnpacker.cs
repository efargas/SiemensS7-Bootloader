using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;

namespace S7.Utils
{
    /// <summary>
    /// A port of the LZP decompression algorithm from lzp.c.
    /// This implementation has been modernized to use more efficient and safer C# idioms.
    /// </summary>
    internal static class LzpDecompressor
    {
        private const int LzpOrder = 4;
        private const int LzpChunkSize = 0x10000; // 65536

        private static uint HashIndex(uint c)
        {
            // Replicate __builtin_bswap32 for consistent hashing with the original C implementation.
            c = (c >> 24) | ((c << 8) & 0x00FF0000) | ((c >> 8) & 0x0000FF00) | (c << 24);
            uint h = ((c >> 15) ^ c) & 0xffffu;
            return h;
        }

        /// <summary>
        /// Unpacks the specified input data.
        /// </summary>
        /// <param name="inputData">A span containing the input data.</param>
        /// <returns>The unpacked data.</returns>
        public static byte[] Unpack(ReadOnlySpan<byte> inputData)
        {
            var hashTable = new uint[LzpChunkSize];
            Array.Fill(hashTable, ~0u);

            using (var outputStream = new MemoryStream())
            {
                if (inputData.Length < LzpOrder)
                    throw new InvalidDataException($"Compressed chunk too short for initial LZPOrder ({inputData.Length} bytes)");

                // First 4 bytes are literals
                outputStream.Write(inputData.Slice(0, LzpOrder));
                int read = LzpOrder;

                // Prime the hash table with the initial literal
                uint c = BitConverter.ToUInt32(inputData.Slice(0, LzpOrder));
                uint h = HashIndex(c);
                hashTable[h] = 0;

                int literalPos = 0;

                while (read < inputData.Length)
                {
                    byte mask = inputData[read++];
                    for (int i = 0; i < 8; i++)
                    {
                        if (read >= inputData.Length) break;

                        if ((mask & 0x80u) == 0) // Literal
                        {
                            byte b = inputData[read++];

                            var buffer = outputStream.GetBuffer();
                            literalPos = (int)outputStream.Position - LzpOrder;
                            c = BitConverter.ToUInt32(buffer, literalPos);
                            h = HashIndex(c);
                            hashTable[h] = (uint)outputStream.Position;

                            outputStream.WriteByte(b);
                        }
                        else // Match
                        {
                            byte b = inputData[read++];

                            var buffer = outputStream.GetBuffer();
                            literalPos = (int)outputStream.Position - LzpOrder;
                            c = BitConverter.ToUInt32(buffer, literalPos);
                            h = HashIndex(c);
                            int pos = (int)hashTable[h];
                            hashTable[h] = (uint)outputStream.Position;

                            if (pos < 0 || pos + b > outputStream.Length)
                            {
                                // Invalid match pointer, skip as per original C code's behavior.
                                continue;
                            }

                            // Efficiently copy the matched block
                            for (int j = 0; j < b; j++)
                            {
                                outputStream.WriteByte(buffer[pos + j]);
                            }
                        }
                        mask <<= 1;
                    }
                }
                return outputStream.ToArray();
            }
        }
    }

    /// <summary>
    /// Represents a raw firmware entry.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 10)]
    public struct FwRawEntry
    {
        public uint Size;
        public uint Crc;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] NameBytes;
        public string Name => Encoding.ASCII.GetString(NameBytes).TrimEnd('\0');
    }

    /// <summary>
    /// Represents a firmware entry.
    /// </summary>
    public class FwEntry
    {
        public long Offset { get; set; }
        public uint Size { get; set; }
        public uint Crc { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    /// <summary>
    /// A utility for unpacking S7 update files.
    /// </summary>
    public class S7UpdateUnpacker
    {
        private const int FwHeaderSize = 0x2c;
        private const int FwNumEntries = 4;
        private const int FwEntryNameSize = 6;
        private const string TargetSectionName = "A00000";

        /// <summary>
        /// Parses the metadata of a firmware file asynchronously.
        /// </summary>
        public async Task<List<FwRawEntry>> ParseMetadataAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var entries = new List<FwRawEntry>();
            int entrySize = Marshal.SizeOf<FwRawEntry>();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(entrySize);
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
                {
                    fs.Seek(FwHeaderSize, SeekOrigin.Begin);
                    for (int i = 0; i < FwNumEntries; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        int bytesRead = await fs.ReadAsync(buffer, 0, entrySize, cancellationToken).ConfigureAwait(false);
                        if (bytesRead < entrySize)
                        {
                            throw new EndOfStreamException("Could not read full firmware entry from file.");
                        }

                        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                        try
                        {
                            var entry = Marshal.PtrToStructure<FwRawEntry>(handle.AddrOfPinnedObject());
                            entries.Add(entry);
                        }
                        finally
                        {
                            handle.Free();
                        }
                    }
                }
                return entries;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        /// <summary>
        /// Unpacks a firmware file asynchronously.
        /// </summary>
        public async Task UnpackAsync(string inputPath, string outputPath, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
        {
            var metadata = await ParseMetadataAsync(inputPath, cancellationToken).ConfigureAwait(false);
            long currentOffset = FwHeaderSize + (FwNumEntries * Marshal.SizeOf<FwRawEntry>());
            FwEntry? targetEntry = null;

            foreach (var rawEntry in metadata)
            {
                if (rawEntry.Name == TargetSectionName)
                {
                    targetEntry = new FwEntry { Name = rawEntry.Name, Size = rawEntry.Size, Crc = rawEntry.Crc, Offset = currentOffset };
                    break;
                }
                currentOffset += rawEntry.Size + FwEntryNameSize;
            }

            if (targetEntry == null)
            {
                throw new FileNotFoundException($"Could not find firmware code section '{TargetSectionName}'.");
            }

            using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
            using (var outFile = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
            {
                fs.Seek(targetEntry.Offset, SeekOrigin.Begin);

                var sectionNameBuffer = ArrayPool<byte>.Shared.Rent(FwEntryNameSize);
                try
                {
                    await fs.ReadAsync(sectionNameBuffer, 0, FwEntryNameSize, cancellationToken).ConfigureAwait(false);
                    if (Encoding.ASCII.GetString(sectionNameBuffer, 0, FwEntryNameSize) != TargetSectionName)
                    {
                        throw new InvalidDataException("Invalid section header.");
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(sectionNameBuffer);
                }

                long readBytes = 0;
                var sizeBuffer = ArrayPool<byte>.Shared.Rent(sizeof(uint));
                try
                {
                    while (readBytes < targetEntry.Size)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        int bytesRead = await fs.ReadAsync(sizeBuffer, 0, sizeof(uint), cancellationToken).ConfigureAwait(false);
                        if (bytesRead < sizeof(uint)) throw new EndOfStreamException("Could not read compressed chunk size.");
                        uint compressedSize = BitConverter.ToUInt32(sizeBuffer, 0);

                        var compressedChunkRented = ArrayPool<byte>.Shared.Rent((int)compressedSize);
                        try
                        {
                            bytesRead = await fs.ReadAsync(compressedChunkRented, 0, (int)compressedSize, cancellationToken).ConfigureAwait(false);
                            if (bytesRead < compressedSize) throw new EndOfStreamException("Could not read full compressed chunk.");

                            if (compressedSize < 2)
                                throw new InvalidDataException($"Compressed chunk is too short ({compressedSize} bytes) at offset {fs.Position - compressedSize}.");

                            var decompressed = LzpDecompressor.Unpack(new ReadOnlySpan<byte>(compressedChunkRented, 2, (int)compressedSize - 2));

                            await outFile.WriteAsync(decompressed, 0, decompressed.Length, cancellationToken).ConfigureAwait(false);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(compressedChunkRented);
                        }

                        readBytes += compressedSize + sizeof(uint);
                        progress?.Report((double)readBytes / targetEntry.Size * 100);
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(sizeBuffer);
                }
            }
        }
    }
}