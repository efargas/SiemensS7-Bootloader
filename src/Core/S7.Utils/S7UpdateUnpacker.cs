using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace S7.Utils
{
    // Port of the LZP decompression algorithm from lzp.c
    internal static class LzpDecompressor
    {
        private const int LzpOrder = 4;
        private const int LzpChunkSize = 0x10000; // 65536

        private static uint HashIndex(uint c)
        {
            // Replicate __builtin_bswap32
            c = (c >> 24) | ((c << 8) & 0x00FF0000) | ((c >> 8) & 0x0000FF00) | (c << 24);
            uint h = ((c >> 15) ^ c) & 0xffffu;
            return h;
        }

        public static byte[] Unpack(byte[] inputData)
        {
            try
            {
                var hashTable = new uint[LzpChunkSize];
                for (int i = 0; i < hashTable.Length; i++)
                {
                    hashTable[i] = ~0u;
                }

                using (var outputStream = new MemoryStream())
                {
                    int read = 0;
                    if (inputData.Length < LzpOrder)
                        throw new Exception($"Compressed chunk too short for initial LZPOrder ({inputData.Length} bytes)");
                    // First 4 bytes are literals
                    outputStream.Write(inputData, 0, LzpOrder);
                    read += LzpOrder;

                    var cBytes = new byte[4];
                    outputStream.Seek(-LzpOrder, SeekOrigin.Current);
                    outputStream.Read(cBytes, 0, 4);
                    uint c = BitConverter.ToUInt32(cBytes, 0);
                    uint h = HashIndex(c);
                    hashTable[h] = (uint)outputStream.Position;
                    outputStream.Seek(0, SeekOrigin.End);

                    while (read < inputData.Length)
                    {
                        byte mask = inputData[read++];
                        for (int i = 0; i < 8; i++)
                        {
                            if (read >= inputData.Length) break;

                            byte b = inputData[read++];

                            if ((mask & 0x80u) == 0)
                            {
                                // Literal
                                var buffer = outputStream.GetBuffer();
                                long posForLiteral = outputStream.Position - LzpOrder;
                                if (posForLiteral < 0 || buffer.Length < posForLiteral + LzpOrder)
                                    throw new Exception($"Decompression error: buffer underrun reading literal (pos={posForLiteral}, buffer length={buffer.Length})");
                                c = BitConverter.ToUInt32(buffer, (int)posForLiteral);
                                h = HashIndex(c);
                                hashTable[h] = (uint)outputStream.Position;

                                outputStream.WriteByte(b);
                            }
                            else
                            {
                                // Match
                                var buffer = outputStream.GetBuffer();
                                long posForMatch = outputStream.Position - LzpOrder;
                                if (posForMatch < 0 || buffer.Length < posForMatch + LzpOrder)
                                    throw new Exception($"Decompression error: buffer underrun reading match (pos={posForMatch}, buffer length={buffer.Length})");
                                c = BitConverter.ToUInt32(buffer, (int)posForMatch);
                                h = HashIndex(c);
                                int pos = (int)hashTable[h];
                                hashTable[h] = (uint)outputStream.Position;
                                // C code: if match pointer is bad, skip match (produce output as-is)
                                if (pos < 0 || pos + b > buffer.Length || pos > (int)outputStream.Position - LzpOrder)
                                {
                                    // Optionally, warn or log debug (but don't throw)
                                    // Skipping invalid match block, copying nothing
                                    continue;
                                }
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
            catch (Exception ex)
            {
                throw new Exception($"LZP decompression failed: {ex.Message}", ex);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 10)]
    public struct FwRawEntry
    {
        public uint Size;
        public uint Crc;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] NameBytes;

        public string Name => Encoding.ASCII.GetString(NameBytes).TrimEnd('\0');
    }

    public class FwEntry
    {
        public long Offset { get; set; }
        public uint Size { get; set; }
        public uint Crc { get; set; }
        public string Name { get; set; }
    }

    public class S7UpdateUnpacker
    {
        private const int FwHeaderSize = 0x2c;
        private const int FwNumEntries = 4;
        private const int FwEntryNameSize = 6;

        public List<FwRawEntry> ParseMetadata(string filePath)
        {
            var entries = new List<FwRawEntry>();
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (var br = new BinaryReader(fs))
            {
                fs.Seek(FwHeaderSize, SeekOrigin.Begin);
                for (int i = 0; i < FwNumEntries; i++)
                {
                    var entryBytes = br.ReadBytes(Marshal.SizeOf(typeof(FwRawEntry)));
                    var handle = GCHandle.Alloc(entryBytes, GCHandleType.Pinned);
                    try
                    {
                        var entry = (FwRawEntry)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(FwRawEntry));
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

        public void Unpack(string inputPath, string outputPath)
        {
            var metadata = ParseMetadata(inputPath);
            long currentOffset = FwHeaderSize + (FwNumEntries * Marshal.SizeOf(typeof(FwRawEntry)));
            FwEntry targetEntry = null;

            foreach(var rawEntry in metadata)
            {
                if (rawEntry.Name == "A00000")
                {
                    targetEntry = new FwEntry
                    {
                        Name = rawEntry.Name,
                        Size = rawEntry.Size,
                        Crc = rawEntry.Crc,
                        Offset = currentOffset
                    };
                    break;
                }
                currentOffset += rawEntry.Size + FwEntryNameSize;
            }

            if (targetEntry == null)
            {
                throw new Exception("Could not find firmware code section 'A00000'.");
            }

            using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var br = new BinaryReader(fs))
            using (var outFile = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                fs.Seek(targetEntry.Offset, SeekOrigin.Begin);

                var sectionNameBytes = br.ReadBytes(FwEntryNameSize);
                if (Encoding.ASCII.GetString(sectionNameBytes) != "A00000")
                {
                    throw new Exception("Invalid section header.");
                }

                long readBytes = 0;
                while (readBytes < targetEntry.Size)
                {
                    uint compressedSize = br.ReadUInt32();
                    // The C code skips the first 2 bytes of the compressed chunk
                    var compressedChunk = br.ReadBytes((int)compressedSize);

                    if (compressedChunk.Length < 2)
                        throw new Exception($"Compressed chunk is too short ({compressedChunk.Length} bytes) at offset {fs.Position - compressedSize}.");

                    var decompressed = LzpDecompressor.Unpack(compressedChunk.Skip(2).ToArray());

                    outFile.Write(decompressed, 0, decompressed.Length);
                    readBytes += compressedSize + sizeof(uint);
                }
            }
        }
    }
}
