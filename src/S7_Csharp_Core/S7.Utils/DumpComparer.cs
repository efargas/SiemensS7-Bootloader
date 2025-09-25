using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            foreach (var file in files)
            {
                _progressReporter?.Invoke($"Hashing {Path.GetFileName(file)}...");
                string hashString = await ComputeFileHashAsync(file).ConfigureAwait(false);
                if (!hashes.ContainsKey(hashString))
                {
                    hashes[hashString] = new List<string>();
                }
                hashes[hashString].Add(file);
            }
            return hashes;
        }

        /// <summary>
        /// Generates a comprehensive report comparing the files in a folder based on their hashes.
        /// </summary>
        /// <param name="hashes">The dictionary of hashes and file paths.</param>
        /// <param name="folderPath">The path to the folder.</param>
        /// <returns>A string containing the detailed comparison report.</returns>
        public string GenerateFolderCompareReport(Dictionary<string, List<string>> hashes, string folderPath)
        {
            var allFiles = Directory.GetFiles(folderPath, "*");
            var fileToHash = new Dictionary<string, string>();
            var fileToSize = new Dictionary<string, long>();

            foreach (var kv in hashes)
            {
                foreach (var f in kv.Value)
                {
                    var fileName = Path.GetFileName(f);
                    fileToHash[fileName] = kv.Key;
                    try
                    {
                        fileToSize[fileName] = new FileInfo(f).Length;
                    }
                    catch
                    {
                        fileToSize[fileName] = 0;
                    }
                }
            }

            var sb = new StringBuilder();
            sb.AppendLine("📁 FOLDER COMPARISON REPORT");
            sb.AppendLine("=" + new string('=', 50));
            sb.AppendLine($"📂 Folder: {folderPath}");
            sb.AppendLine($"📊 Total Files: {allFiles.Length}");
            sb.AppendLine($"🔍 Unique Hashes: {hashes.Count}");
            sb.AppendLine($"📅 Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            sb.AppendLine("📋 FILES AND THEIR MD5 HASHES:");
            sb.AppendLine("-" + new string('-', 80));
            sb.AppendLine($"{"File Name",-30} {"Size",-12} {"MD5 Hash",-32}");
            sb.AppendLine("-" + new string('-', 80));

            foreach (var filePath in allFiles.OrderBy(f => Path.GetFileName(f)))
            {
                var fileName = Path.GetFileName(filePath);
                if (fileToHash.TryGetValue(fileName, out var hash))
                {
                    var size = fileToSize.TryGetValue(fileName, out var s) ? FormatFileSize(s) : "Unknown";
                    sb.AppendLine($"{fileName,-30} {size,-12} {hash.ToUpperInvariant()}");
                }
                else
                {
                    sb.AppendLine($"{fileName,-30} {"Error",-12} {"[ERROR COMPUTING HASH]",-32}");
                }
            }

            sb.AppendLine();
            sb.AppendLine("🔗 DUPLICATE GROUPS (Files with identical MD5 hashes):");
            sb.AppendLine("-" + new string('-', 60));

            int groupNum = 1;
            int duplicateFiles = 0;

            foreach (var kv in hashes.Where(h => h.Value.Count > 1))
            {
                var hash = kv.Key;
                var flist = kv.Value;
                duplicateFiles += flist.Count;

                sb.AppendLine($"Group {groupNum++} - {flist.Count} identical files:");
                sb.AppendLine($"  �� MD5: {hash.ToUpperInvariant()}");

                foreach (var filePath in flist.OrderBy(f => Path.GetFileName(f)))
                {
                    var fileName = Path.GetFileName(filePath);
                    var size = fileToSize.TryGetValue(fileName, out var s) ? FormatFileSize(s) : "Unknown";
                    sb.AppendLine($"  📄 {fileName} ({size})");
                }
                sb.AppendLine();
            }

            if (duplicateFiles == 0)
            {
                sb.AppendLine("✅ No duplicate files found - all files are unique!");
            }
            else
            {
                sb.AppendLine($"⚠️  Found {duplicateFiles} duplicate files in {hashes.Count(h => h.Value.Count > 1)} groups");
            }

            sb.AppendLine();
            sb.AppendLine("📈 SUMMARY:");
            sb.AppendLine("-" + new string('-', 30));
            sb.AppendLine($"Total Files Analyzed: {allFiles.Length}");
            sb.AppendLine($"Unique Files: {allFiles.Length - duplicateFiles + hashes.Count(h => h.Value.Count > 1)}");
            sb.AppendLine($"Duplicate Files: {duplicateFiles}");
            sb.AppendLine($"Space Savings Potential: {CalculateSpaceSavings(hashes, fileToSize)}");

            return sb.ToString();
        }

        /// <summary>
        /// Formats a file size in bytes to a human-readable string.
        /// </summary>
        /// <param name="bytes">The file size in bytes.</param>
        /// <returns>A formatted file size string.</returns>
        private static string FormatFileSize(long bytes)
        {
            if (bytes == 0) return "0 B";

            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;

            while (Math.Round(number / 1024) >= 1 && counter < suffixes.Length - 1)
            {
                number /= 1024;
                counter++;
            }

            return $"{number:n1} {suffixes[counter]}";
        }

        /// <summary>
        /// Calculates potential space savings from removing duplicate files.
        /// </summary>
        /// <param name="hashes">The dictionary of hashes and file paths.</param>
        /// <param name="fileToSize">The dictionary mapping file names to sizes.</param>
        /// <returns>A formatted string showing potential space savings.</returns>
        private static string CalculateSpaceSavings(Dictionary<string, List<string>> hashes, Dictionary<string, long> fileToSize)
        {
            long totalSavings = 0;

            foreach (var kv in hashes.Where(h => h.Value.Count > 1))
            {
                var duplicateFiles = kv.Value;
                if (duplicateFiles.Count > 1)
                {
                    var fileName = Path.GetFileName(duplicateFiles[0]);
                    if (fileToSize.TryGetValue(fileName, out var fileSize))
                    {
                        // Savings = (number of duplicates - 1) * file size
                        totalSavings += (duplicateFiles.Count - 1) * fileSize;
                    }
                }
            }

            return totalSavings > 0 ? FormatFileSize(totalSavings) : "None";
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
                var hashBytes = await md5.ComputeHashAsync(stream).ConfigureAwait(false);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
