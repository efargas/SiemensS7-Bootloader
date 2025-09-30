using S7.Infrastructure;
using S7.Utils.Interfaces;

namespace S7.Services
{
    /// <summary>
    /// A factory for creating virtual file readers.
    /// </summary>
    public class VirtualFileReaderFactory : IVirtualFileReaderFactory
    {
        /// <summary>
        /// Creates a virtual file reader for the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>An instance of a virtual file reader.</returns>
        public IVirtualFileReader Create(string filePath)
        {
            // In the future, we could add logic to choose the best reader
            // based on file size or other heuristics.
            var baseReader = new MemoryMappedFileVirtualReader(filePath);
            var cachedReader = new PageCache(baseReader);
            return cachedReader;
        }
    }
}