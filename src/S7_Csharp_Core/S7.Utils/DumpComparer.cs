using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace S7.Utils
{
    /// <summary>
    /// A utility for comparing memory dumps.
    /// </summary>
    public class DumpComparer
    {
        private readonly Action<string>? _progressReporter;

        /// <summary>
        /// Initializes a new instance of the <see cref="DumpComparer"/> class.
        /// </summary>
        /// <param name="progressReporter">An action to report progress to.</param>
        public DumpComparer(Action<string>? progressReporter = null)
        {
            _progressReporter = progressReporter;
        }

        /// <summary>
        /// Computes the MD5 hashes of all files in a folder.
        /// </summary>
        /// <param name="folderPath">The path to the folder.</param>
        /// <returns>A dictionary mapping hashes to a list of file paths.</returns>
        public async Task<Dictionary<string, List<string>>> ComputeFileHashesAsync(string folderPath)
        {
            var hashes = new Dictionary<string, List<string>>();
            var files = Directory.GetFiles(folderPath, "*");
            using (var md5 = MD5.Create())
            {
                foreach (var file in files)
                {
                    _progressReporter?.Invoke($"Hashing {Path.GetFileName(file)}...");
                    using (var stream = File.OpenRead(file))
                    {
                        var hashBytes = await md5.ComputeHashAsync(stream);
                        string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                        if (!hashes.ContainsKey(hashString))
                        {
                            hashes[hashString] = new List<string>();
                        }
                        hashes[hashString].Add(file);
                    }
                }
            }
            return hashes;
        }

        /// <summary>
        /// Generates a report comparing the files in a folder based on their hashes.
        /// </summary>
        /// <param name="hashes">The dictionary of hashes and file paths.</param>
        /// <param name="folderPath">The path to the folder.</param>
        /// <returns>A string containing the comparison report.</returns>
        public string GenerateFolderCompareReport(Dictionary<string, List<string>> hashes, string folderPath)
        {
            var allFiles = Directory.GetFiles(folderPath, "*");
            var fileToHash = new Dictionary<string, string>();
            foreach (var kv in hashes)
            {
                foreach (var f in kv.Value)
                {
                    fileToHash[Path.GetFileName(f)] = kv.Key;
                }
            }

            var sb = new StringBuilder();
            sb.AppendLine("Files and their MD5 hashes:");
            foreach (var filePath in allFiles)
            {
                var fileName = Path.GetFileName(filePath);
                if (fileToHash.TryGetValue(fileName, out var hash))
                {
                    sb.AppendLine($"{fileName} : {hash}");
                }
                else
                {
                    sb.AppendLine($"{fileName} : [error computing hash]");
                }
            }
            sb.AppendLine();
            sb.AppendLine("Groups by identical hash:");
            int groupNum = 1;
            foreach (var kv in hashes)
            {
                var hash = kv.Key;
                var flist = kv.Value;
                sb.AppendLine($"Group {groupNum++} (Hash: {hash}):");
                foreach (var fn in flist)
                {
                    sb.AppendLine($"  {fn}");
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Computes the MD5 hash of a file.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The MD5 hash of the file.</returns>
        public async Task<string> ComputeFileHashAsync(string path)
        {
            using (var md5 = MD5.Create())
            using (var stream = File.OpenRead(path))
            {
                var hashBytes = await md5.ComputeHashAsync(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
