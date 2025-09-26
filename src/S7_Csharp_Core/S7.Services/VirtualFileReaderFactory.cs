using Microsoft.Extensions.Options;
using S7.Infrastructure;
using S7.Services.Configuration;
using S7.Services.Interfaces;
using S7.Utils.Interfaces;

namespace S7.Services
{
    /// <summary>
    /// Factory for creating virtual file readers with dependency injection support.
    /// Provides configuration-driven reader selection and caching capabilities.
    /// </summary>
    public class VirtualFileReaderFactory(IOptions<VirtualFileReaderConfiguration> options) : IVirtualFileReaderFactory
    {
        private readonly VirtualFileReaderConfiguration _configuration = options?.Value ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Creates a virtual file reader for the specified file path using default configuration.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <returns>A configured virtual file reader instance.</returns>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        public IVirtualFileReader Create(string filePath)
        {
            ValidateFilePath(filePath);

            var readerType = _configuration.EnableAutoSelection 
                ? DetermineOptimalReaderType(filePath) 
                : _configuration.DefaultReaderType;

            return Create(filePath, readerType, _configuration.EnableCaching, _configuration.DefaultPageSize);
        }

        /// <summary>
        /// Creates a virtual file reader for the specified file path with explicit reader type.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <param name="readerType">The type of reader to create.</param>
        /// <returns>A configured virtual file reader instance.</returns>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        public IVirtualFileReader Create(string filePath, VirtualFileReaderType readerType)
        {
            ValidateFilePath(filePath);
            return Create(filePath, readerType, _configuration.EnableCaching, _configuration.DefaultPageSize);
        }

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
        public IVirtualFileReader Create(string filePath, VirtualFileReaderType readerType, bool enableCaching, int? pageSize = null)
        {
            ValidateFilePath(filePath);

            var effectivePageSize = pageSize ?? _configuration.DefaultPageSize;
            IVirtualFileReader baseReader = CreateBaseReader(filePath, readerType, effectivePageSize);

            if (enableCaching)
            {
                return new PageCache(baseReader, _configuration.CacheSize);
            }

            return baseReader;
        }

        /// <summary>
        /// Creates the base reader without caching based on the specified type.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <param name="readerType">The type of reader to create.</param>
        /// <param name="pageSize">The page size to use.</param>
        /// <returns>A base virtual file reader instance.</returns>
        private static IVirtualFileReader CreateBaseReader(string filePath, VirtualFileReaderType readerType, int pageSize)
        {
            return readerType switch
            {
                VirtualFileReaderType.MemoryMapped => new MemoryMappedFileVirtualReader(filePath, pageSize),
                VirtualFileReaderType.FileStream => new FileStreamVirtualReader(filePath, pageSize),
                _ => throw new ArgumentException($"Unsupported reader type: {readerType}", nameof(readerType))
            };
        }

        /// <summary>
        /// Determines the optimal reader type based on file size and configuration.
        /// </summary>
        /// <param name="filePath">The path to the file to analyze.</param>
        /// <returns>The recommended reader type.</returns>
        private VirtualFileReaderType DetermineOptimalReaderType(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                return fileInfo.Length >= _configuration.MemoryMappedThreshold 
                    ? VirtualFileReaderType.MemoryMapped 
                    : VirtualFileReaderType.FileStream;
            }
            catch
            {
                // If we can't determine file size, use the default
                return _configuration.DefaultReaderType;
            }
        }

        /// <summary>
        /// Validates the file path parameter.
        /// </summary>
        /// <param name="filePath">The file path to validate.</param>
        /// <exception cref="ArgumentException">Thrown when filePath is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist and validation is enabled.</exception>
        private void ValidateFilePath(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            if (_configuration.ValidateFileExistence && !File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}", filePath);
            }
        }
    }

    /// <summary>
    /// Static factory class for backward compatibility.
    /// This maintains the existing API while providing a migration path to the DI-based factory.
    /// </summary>
    public static class VirtualFileReaderFactoryLegacy
    {
        private static readonly Lazy<IVirtualFileReaderFactory> _defaultFactory = new(() =>
        {
            var defaultConfig = Microsoft.Extensions.Options.Options.Create(new VirtualFileReaderConfiguration());
            return new VirtualFileReaderFactory(defaultConfig);
        });

        /// <summary>
        /// Creates a virtual file reader using default configuration.
        /// This method is maintained for backward compatibility.
        /// </summary>
        /// <param name="filePath">The path to the file to read.</param>
        /// <returns>A configured virtual file reader instance.</returns>
        [Obsolete("Use IVirtualFileReaderFactory through dependency injection instead. This method will be removed in a future version.")]
        public static IVirtualFileReader Create(string filePath)
        {
            return _defaultFactory.Value.Create(filePath);
        }
    }
}
