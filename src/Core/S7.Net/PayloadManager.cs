using System.IO;

namespace S7.Net
{
    /// <summary>
    /// Manages loading payloads from the file system.
    /// </summary>
    public class PayloadManager
    {
        private readonly string _baseDirectory;

        /// <summary>
        /// Initializes a new instance of the <see cref="PayloadManager"/> class.
        /// </summary>
        /// <param name="baseDirectory">The base directory where payloads are stored.</param>
        public PayloadManager(string baseDirectory)
        {
            _baseDirectory = baseDirectory;
        }

        /// <summary>
        /// Gets the stager payload.
        /// </summary>
        /// <returns>The stager payload as a byte array.</returns>
        public byte[] GetStagerPayload(string payloadsBase)
        {
            return LoadPayload(payloadsBase, "stager", "stager.bin");
        }

        /// <summary>
        /// Gets the memory dumper payload.
        /// </summary>
        /// <returns>The memory dumper payload as a byte array.</returns>
        public byte[] GetMemoryDumperPayload(string payloadsBase)
        {
            return LoadPayload(payloadsBase, "dump_mem", "build", "dump_mem.bin");
        }

        /// <summary>
        /// Loads a payload from the file system.
        /// </summary>
        /// <param name="pathSegments">The path segments of the payload file.</param>
        /// <returns>The payload as a byte array.</returns>
        private byte[] LoadPayload(string payloadsBase, params string[] pathSegments)
        {
            var fullPath = payloadsBase;
            foreach(var segment in pathSegments)
            {
                fullPath = Path.Combine(fullPath, segment);
            }
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException($"Payload not found at {fullPath}");
            }
            return File.ReadAllBytes(fullPath);
        }
    }
}
