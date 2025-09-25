namespace S7.Utils
{
    /// <summary>
    /// Common constants used throughout the application.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// Buffer and memory size constants.
        /// </summary>
        public static class BufferSizes
        {
            /// <summary>
            /// Standard buffer size for temporary operations (256 bytes).
            /// </summary>
            public const int TempBuffer = 256;

            /// <summary>
            /// Standard page size for file operations (4KB).
            /// </summary>
            public const int StandardPageSize = 4096;

            /// <summary>
            /// Large chunk size for file processing (64KB).
            /// </summary>
            public const int LargeChunkSize = 64 * 1024;

            /// <summary>
            /// Maximum log file size (5MB).
            /// </summary>
            public const long MaxLogFileSize = 5 * 1024 * 1024;

            /// <summary>
            /// Maximum memory dump size (256MB).
            /// </summary>
            public const uint MaxMemoryDumpSize = 256 * 1024 * 1024;
        }

        /// <summary>
        /// Protocol-specific constants.
        /// </summary>
        public static class Protocol
        {
            /// <summary>
            /// Maximum payload size for protocol messages (255 bytes).
            /// </summary>
            public const int MaxPayloadSize = 255;

            /// <summary>
            /// Number of bytes per hex viewer line.
            /// </summary>
            public const int HexBytesPerLine = 16;

            /// <summary>
            /// Maximum XOR key search range.
            /// </summary>
            public const int MaxXorKeyRange = 256;
        }

        /// <summary>
        /// File system constants.
        /// </summary>
        public static class FileSystem
        {
            /// <summary>
            /// Standard file buffer size for async operations.
            /// </summary>
            public const int FileBufferSize = 4096;

            /// <summary>
            /// Bytes per kilobyte conversion factor.
            /// </summary>
            public const int BytesPerKilobyte = 1024;
        }

        /// <summary>
        /// Timeout constants.
        /// </summary>
        public static class Timeouts
        {
            /// <summary>
            /// Handshake response timeout in milliseconds.
            /// </summary>
            public const int HandshakeTimeoutMs = 300;

            /// <summary>
            /// Safety delay between chunk sends in milliseconds.
            /// </summary>
            public const int ChunkSafetyDelayMs = 10;

            /// <summary>
            /// Brief retry delay in milliseconds.
            /// </summary>
            public const int BriefRetryDelayMs = 10;

            /// <summary>
            /// Standard polling interval in milliseconds.
            /// </summary>
            public const int StandardPollingIntervalMs = 50;
        }
    }
}