using S7.Services.Configuration;
using S7.Utils.Interfaces;

namespace S7.Services.Interfaces
{
    /// <summary>
    /// Factory interface for creating virtual file readers with dependency injection support.
    /// </summary>
    public interface IVirtualFileReaderFactory
    {
        /// <summary>
        /// Creates a virtual file reader for the specified file path using default configuration.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <returns>A configured virtual file reader instance.</returns>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        IVirtualFileReader Create(string filePath);

        /// <summary>
        /// Creates a virtual file reader for the specified file path with explicit reader type.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <param name="readerType">The type of reader to create.</param>
        /// <returns>A configured virtual file reader instance.</returns>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        IVirtualFileReader Create(string filePath, VirtualFileReaderType readerType);

        /// <summary>
        /// Creates a virtual file reader for the specified file path with custom configuration.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <param name="readerType">The type of reader to create.</param>
        /// <param name="enableCaching">Whether to enable page caching.</param>
        /// <param name="pageSize">The page size to use (optional).</param>
        /// <returns>A configured virtual file reader instance.</returns>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        IVirtualFileReader Create(string filePath, VirtualFileReaderType readerType, bool enableCaching, int? pageSize = null);
    }
}