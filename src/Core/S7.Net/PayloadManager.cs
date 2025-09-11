using System.IO;

namespace S7.Net
{
    public class PayloadManager
    {
        private readonly string _baseDirectory;

        public PayloadManager(string baseDirectory)
        {
            _baseDirectory = baseDirectory;
        }

        public byte[] GetStagerPayload()
        {
            return LoadPayload("stager", "stager.bin");
        }

        public byte[] GetMemoryDumperPayload()
        {
            return LoadPayload("dump_mem", "build", "dump_mem.bin");
        }

        private byte[] LoadPayload(params string[] pathSegments)
        {
            var fullPath = Path.Combine(_baseDirectory, "payloads");
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
