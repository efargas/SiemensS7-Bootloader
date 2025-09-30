using S7.Utils.Interfaces;

namespace S7.Services
{
    /// <summary>
    /// Defines a factory for creating virtual file readers.
    /// </summary>
    public interface IVirtualFileReaderFactory
    {
        /// <summary>
        /// Creates a virtual file reader for the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>An instance of a virtual file reader.</returns>
        IVirtualFileReader Create(string filePath);
    }
}