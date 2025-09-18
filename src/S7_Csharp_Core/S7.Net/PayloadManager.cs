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
            var filePath = FindPayloadFile(payloadsBase, "stager.bin");
            return File.ReadAllBytes(filePath);
        }

        /// <summary>
        /// Gets the memory dumper payload.
        /// </summary>
        /// <returns>The memory dumper payload as a byte array.</returns>
        public byte[] GetMemoryDumperPayload(string payloadsBase)
        {
            var filePath = FindPayloadFile(payloadsBase, "dump_mem.bin");
            return File.ReadAllBytes(filePath);
        }

        /// <summary>
        /// Recursively searches for the payload file in the base directory.
        /// </summary>
        private static string FindPayloadFile(string payloadsBase, string fileName)
        {
            foreach (var file in Directory.GetFiles(payloadsBase, fileName, SearchOption.AllDirectories))
            {
                return file; // Return first match
            }
            throw new FileNotFoundException($"Payload {fileName} not found anywhere under {payloadsBase}");
        }
    }
}
