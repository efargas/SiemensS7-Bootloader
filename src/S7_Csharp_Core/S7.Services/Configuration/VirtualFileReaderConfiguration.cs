using System.ComponentModel.DataAnnotations;

namespace S7.Services.Configuration
{
    /// <summary>
    /// Configuration options for virtual file reader factory.
    /// </summary>
    public class VirtualFileReaderConfiguration
    {
        /// <summary>
        /// The configuration section name.
        /// </summary>
        public const string SectionName = "VirtualFileReader";

        /// <summary>
        /// Gets or sets the default reader type to use.
        /// </summary>
        [Required]
        public VirtualFileReaderType DefaultReaderType { get; set; } = VirtualFileReaderType.MemoryMapped;

        /// <summary>
        /// Gets or sets whether to enable page caching.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache size in pages.
        /// </summary>
        [Range(1, 10000)]
        public int CacheSize { get; set; } = 100;

        /// <summary>
        /// Gets or sets the default page size in bytes.
        /// </summary>
        [Range(1024, 1048576)] // 1KB to 1MB
        public int DefaultPageSize { get; set; } = 4096;

        /// <summary>
        /// Gets or sets the file size threshold for automatic reader type selection (in bytes).
        /// Files larger than this threshold will use memory-mapped readers.
        /// </summary>
        [Range(1024, long.MaxValue)]
        public long MemoryMappedThreshold { get; set; } = 10 * 1024 * 1024; // 10MB

        /// <summary>
        /// Gets or sets whether to enable automatic reader type selection based on file size.
        /// </summary>
        public bool EnableAutoSelection { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to validate file existence before creating readers.
        /// </summary>
        public bool ValidateFileExistence { get; set; } = true;
    }

    /// <summary>
    /// Enumeration of available virtual file reader types.
    /// </summary>
    public enum VirtualFileReaderType
    {
        /// <summary>
        /// Memory-mapped file reader for large files.
        /// </summary>
        MemoryMapped,

        /// <summary>
        /// File stream reader for smaller files.
        /// </summary>
        FileStream
    }
}