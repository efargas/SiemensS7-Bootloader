using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PLCSploit.Core
{
    // Centralized logging service inspired by uart-config branch implementation
    public static class LoggingService
    {
        private static readonly object _sync = new object();
        private static readonly Queue<LogEntry> _allLogEntries = new Queue<LogEntry>();
        private const int MaxLogLines = 2000;

        private static readonly string _logsDir;
        private static readonly string _logFilePath;
        private const long MaxFileSizeBytes = 5 * 1024 * 1024; // 5 MB rotation threshold

        static LoggingService()
        {
            // Use GetFullPath to normalize and secure the path
            _logsDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs"));
            Directory.CreateDirectory(_logsDir);
            _logFilePath = Path.Combine(_logsDir, "log.txt");
        }

        public static void Log(LogEntry entry)
        {
            // Keep in-memory bounded queue - O(1) operations for better performance
            lock (_sync)
            {
                _allLogEntries.Enqueue(entry);
                if (_allLogEntries.Count > MaxLogLines)
                {
                    _allLogEntries.Dequeue(); // O(1) instead of O(n) RemoveAt(0)
                }
            }

            // Persist to file with rotation - use lock to prevent race conditions
            lock (_sync)
            {
                try
                {
                    EnsureRotation();
                    var line = FormatLine(entry);
                    File.AppendAllText(_logFilePath, line + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception ex)
                {
                    // Log to console as fallback to avoid silent failures
                    Console.WriteLine($"[LoggingService] Failed to write log: {ex.Message}");
                }
            }
        }

        public static void Clear()
        {
            lock (_sync)
            {
                _allLogEntries.Clear();
                try
                {
                    if (File.Exists(_logFilePath))
                    {
                        File.WriteAllText(_logFilePath, string.Empty, Encoding.UTF8);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[LoggingService] Failed to clear log file: {ex.Message}");
                }
            }
        }

        public static void ExportLogs()
        {
            try
            {
                Directory.CreateDirectory(_logsDir);
                var exportPath = Path.Combine(_logsDir, $"exported_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                List<LogEntry> snapshot;
                lock (_sync)
                {
                    snapshot = new List<LogEntry>(_allLogEntries);
                }
                using var writer = new StreamWriter(exportPath, false, Encoding.UTF8);
                foreach (var e in snapshot)
                {
                    writer.WriteLine(FormatLine(e));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LoggingService] Failed to export logs: {ex.Message}");
            }
        }

        public static string GetCurrentLogFile()
        {
            return _logFilePath;
        }

        public static void LogSeparator(string title = "")
        {
            string separator;
            if (string.IsNullOrEmpty(title))
            {
                separator = new string('=', 80);
            }
            else
            {
                var padding = Math.Max(0, (80 - title.Length - 2) / 2);
                separator = new string('=', padding) + $" {title} " + new string('=', Math.Max(0, 80 - padding - title.Length - 2));
            }
            Log(new LogEntry(separator, LogCategory.Info));
        }

        private static string FormatLine(LogEntry entry)
        {
            // Match uart-config style: "[timestamp] Category Message"
            return $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}";
        }

        private static void EnsureRotation()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    var info = new FileInfo(_logFilePath);
                    if (info.Length > MaxFileSizeBytes)
                    {
                        // Find next available rotated file name: log_1.txt, log_2.txt, ...
                        int idx = 1;
                        string rotatedPath;
                        do
                        {
                            rotatedPath = Path.Combine(_logsDir, $"log_{idx}.txt");
                            idx++;
                        }
                        while (File.Exists(rotatedPath));
                        File.Move(_logFilePath, rotatedPath);
                    }
                }
                else
                {
                    // ensure directory exists
                    Directory.CreateDirectory(_logsDir);
                }
            }
            catch (Exception ex)
            {
                // Log rotation failures to console - these are important for disk space management
                Console.WriteLine($"[LoggingService] Failed to rotate log file: {ex.Message}");
            }
        }
    }
}
