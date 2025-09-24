using S7.Infrastructure;
using S7.Utils.Interfaces;

namespace S7.Services
{
    public static class VirtualFileReaderFactory
    {
        public static IVirtualFileReader Create(string filePath)
        {
            // In the future, we could add logic to choose the best reader
            // based on file size or other heuristics.
            var baseReader = new MemoryMappedFileVirtualReader(filePath);
            var cachedReader = new PageCache(baseReader);
            return cachedReader;
        }
    }
}
